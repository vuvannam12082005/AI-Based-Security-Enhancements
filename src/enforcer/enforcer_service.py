from fastapi import FastAPI, HTTPException
from shared.contracts.enforcer_contracts import EnforcerActionRequest, EnforcerReleaseRequest
import os, signal

app = FastAPI(title="Enforcer Service", version="0.1")

BASE = "ai-sec"
CPU_MNT = "/sys/fs/cgroup/cpu"
MEM_MNT = "/sys/fs/cgroup/memory"

def _write(path: str, value: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)

def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def _parse_cpu_max(cpu_max: str):
    try:
        quota_s, period_s = cpu_max.split()
        return int(quota_s), int(period_s)
    except Exception:
        raise HTTPException(status_code=400, detail='cpu_max must be like "20000 100000"')

@app.get("/enforcer/status")
def status():
    return {
        "ok": True,
        "engine": "cgroupv1",
        "cpu_mount": CPU_MNT if os.path.isdir(CPU_MNT) else None,
        "mem_mount": MEM_MNT if os.path.isdir(MEM_MNT) else None,
        "note": "WSL2 cgroupv2 controllers are empty; using cgroup v1 mounts."
    }

@app.post("/enforcer/action")
def action(req: EnforcerActionRequest):
    if req.action not in ("throttle", "kill"):
        raise HTTPException(status_code=400, detail="invalid action")

    if req.action == "kill":
        try:
            os.kill(req.pid, signal.SIGKILL)
        except ProcessLookupError:
            raise HTTPException(status_code=404, detail="pid not found")
        return {"ok": True, "action": "kill", "pid": req.pid}

    # throttle
    if not os.path.isdir(CPU_MNT) and not os.path.isdir(MEM_MNT):
        raise HTTPException(status_code=500, detail="cgroup v1 mounts not available")

    info = {"ok": True, "action": "throttle", "pid": req.pid, "engine": "cgroupv1"}

    if os.path.isdir(CPU_MNT):
        cg_cpu = os.path.join(CPU_MNT, BASE, str(req.pid))
        _ensure_dir(cg_cpu)
        if req.cpu_max:
            quota, period = _parse_cpu_max(req.cpu_max)
            _write(os.path.join(cg_cpu, "cpu.cfs_period_us"), str(period))
            _write(os.path.join(cg_cpu, "cpu.cfs_quota_us"), str(quota))
        _write(os.path.join(cg_cpu, "tasks"), str(req.pid))
        info["cpu_cgroup"] = cg_cpu

    if os.path.isdir(MEM_MNT) and req.memory_max is not None:
        cg_mem = os.path.join(MEM_MNT, BASE, str(req.pid))
        _ensure_dir(cg_mem)
        _write(os.path.join(cg_mem, "memory.limit_in_bytes"), str(req.memory_max))
        _write(os.path.join(cg_mem, "tasks"), str(req.pid))
        info["mem_cgroup"] = cg_mem

    return info

@app.post("/enforcer/release")
def release(req: EnforcerReleaseRequest):
    # best-effort: move pid back to root and cleanup
    if os.path.isdir(CPU_MNT):
        try: _write(os.path.join(CPU_MNT, "tasks"), str(req.pid))
        except Exception: pass
        try: os.rmdir(os.path.join(CPU_MNT, BASE, str(req.pid)))
        except Exception: pass

    if os.path.isdir(MEM_MNT):
        try: _write(os.path.join(MEM_MNT, "tasks"), str(req.pid))
        except Exception: pass
        try: os.rmdir(os.path.join(MEM_MNT, BASE, str(req.pid)))
        except Exception: pass

    return {"ok": True, "pid": req.pid, "released": True, "engine": "cgroupv1"}
