from fastapi import FastAPI, HTTPException
from shared.contracts.enforcer_contracts import EnforcerActionRequest, EnforcerReleaseRequest
import os, signal

from src.enforcer.cgroups.cgroup_manager import CgroupV2Manager

app = FastAPI(title="Enforcer Service", version="0.3")

BASE = "ai-sec"

# v1 mounts (fallback for WSL2)
CPU_V1 = "/sys/fs/cgroup/cpu"
MEM_V1 = "/sys/fs/cgroup/memory"

def _write(path: str, value: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)

def _parse_cpu_max(cpu_max: str):
    try:
        quota_s, period_s = cpu_max.split()
        return int(quota_s), int(period_s)
    except Exception:
        raise HTTPException(status_code=400, detail='cpu_max must be like "20000 100000"')

def is_cgroup2fs(mount: str = "/sys/fs/cgroup") -> bool:
    try:
        st = os.statvfs(mount)
        # can't easily detect by statvfs; use /proc/self/mounts instead
        with open("/proc/self/mounts", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == mount and parts[2] == "cgroup2":
                    return True
    except Exception:
        pass
    return False

def cgv2_has_controllers(mount: str = "/sys/fs/cgroup") -> bool:
    try:
        with open(os.path.join(mount, "cgroup.controllers"), "r", encoding="utf-8") as f:
            ctrls = f.read().strip().split()
        return ("cpu" in ctrls) or ("memory" in ctrls)
    except Exception:
        return False

def enforcer_engine():
    # v2 primary if available
    if is_cgroup2fs("/sys/fs/cgroup") and cgv2_has_controllers("/sys/fs/cgroup"):
        return "cgroupv2"
    return "cgroupv1"

@app.get("/enforcer/status")
def status():
    engine = enforcer_engine()
    controllers = ""
    try:
        with open("/sys/fs/cgroup/cgroup.controllers", "r", encoding="utf-8") as f:
            controllers = f.read().strip()
    except Exception:
        pass
    return {
        "ok": True,
        "engine": engine,
        "v2": {"mount": "/sys/fs/cgroup", "controllers": controllers},
        "v1": {"cpu_mount": CPU_V1 if os.path.isdir(CPU_V1) else None,
               "mem_mount": MEM_V1 if os.path.isdir(MEM_V1) else None},
        "base": BASE
    }

def throttle_v2(pid: int, cpu_max: str | None, memory_max: int | None):
    cg = CgroupV2Manager(mount="/sys/fs/cgroup", base=BASE)
    cg_path = cg.create_for_pid(pid)
    cg.move_pid(pid, cg_path)
    if cpu_max:
        cg.set_cpu_max(cg_path, cpu_max)
    if memory_max is not None:
        cg.set_memory_max(cg_path, memory_max)
    return {"engine": "cgroupv2", "cgroup": cg_path}

def throttle_v1(pid: int, cpu_max: str | None, memory_max: int | None):
    if not os.path.isdir(CPU_V1) and not os.path.isdir(MEM_V1):
        raise HTTPException(status_code=500, detail="cgroup v1 mounts not available")

    out = {"engine": "cgroupv1"}

    if os.path.isdir(CPU_V1):
        cg_cpu = os.path.join(CPU_V1, BASE, str(pid))
        os.makedirs(cg_cpu, exist_ok=True)
        if cpu_max:
            quota, period = _parse_cpu_max(cpu_max)
            _write(os.path.join(cg_cpu, "cpu.cfs_period_us"), str(period))
            _write(os.path.join(cg_cpu, "cpu.cfs_quota_us"), str(quota))
        _write(os.path.join(cg_cpu, "tasks"), str(pid))
        out["cpu_cgroup"] = cg_cpu

    if os.path.isdir(MEM_V1) and memory_max is not None:
        cg_mem = os.path.join(MEM_V1, BASE, str(pid))
        os.makedirs(cg_mem, exist_ok=True)
        _write(os.path.join(cg_mem, "memory.limit_in_bytes"), str(memory_max))
        _write(os.path.join(cg_mem, "tasks"), str(pid))
        out["mem_cgroup"] = cg_mem

    return out

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
    try:
        if enforcer_engine() == "cgroupv2":
            info = throttle_v2(req.pid, req.cpu_max, req.memory_max)
        else:
            info = throttle_v1(req.pid, req.cpu_max, req.memory_max)
    except PermissionError as e:
        raise HTTPException(status_code=500, detail=f"permission denied (run as root): {e}")

    return {"ok": True, "action": "throttle", "pid": req.pid, **info}

@app.post("/enforcer/release")
def release(req: EnforcerReleaseRequest):
    # best effort: v2 set max; v1 move back to root tasks
    if enforcer_engine() == "cgroupv2":
        cg_path = os.path.join("/sys/fs/cgroup", BASE, str(req.pid))
        if not os.path.isdir(cg_path):
            raise HTTPException(status_code=404, detail="cgroup not found")
        try:
            if os.path.exists(os.path.join(cg_path, "cpu.max")):
                _write(os.path.join(cg_path, "cpu.max"), "max 100000")
            if os.path.exists(os.path.join(cg_path, "memory.max")):
                _write(os.path.join(cg_path, "memory.max"), "max")
        except PermissionError as e:
            raise HTTPException(status_code=500, detail=f"permission denied (run as root): {e}")
        return {"ok": True, "pid": req.pid, "released": True, "engine": "cgroupv2"}

    # v1 fallback
    if os.path.isdir(CPU_V1):
        try: _write(os.path.join(CPU_V1, "tasks"), str(req.pid))
        except Exception: pass
    if os.path.isdir(MEM_V1):
        try: _write(os.path.join(MEM_V1, "tasks"), str(req.pid))
        except Exception: pass

    return {"ok": True, "pid": req.pid, "released": True, "engine": "cgroupv1"}
