import os

def _write(path: str, value: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)

class CgroupV2Manager:
    def __init__(self, mount: str = "/sys/fs/cgroup", base: str = "ai-sec"):
        self.mount = mount
        self.base = base
        self.base_path = os.path.join(self.mount, self.base)

    def ensure_base(self) -> None:
        os.makedirs(self.base_path, exist_ok=True)

        controllers_path = os.path.join(self.base_path, "cgroup.controllers")
        subtree_path = os.path.join(self.base_path, "cgroup.subtree_control")

        if os.path.exists(controllers_path) and os.path.exists(subtree_path):
            with open(controllers_path, "r", encoding="utf-8") as f:
                ctrls = f.read().strip().split()
            want = [c for c in ("cpu", "memory", "pids", "io") if c in ctrls]
            if want:
                # best effort enable
                try:
                    _write(subtree_path, " ".join([f"+{c}" for c in want]))
                except Exception:
                    pass

    def path_for_pid(self, pid: int) -> str:
        return os.path.join(self.base_path, str(pid))

    def create_for_pid(self, pid: int) -> str:
        self.ensure_base()
        cg = self.path_for_pid(pid)
        os.makedirs(cg, exist_ok=True)
        return cg

    def move_pid(self, pid: int, cg_path: str) -> None:
        _write(os.path.join(cg_path, "cgroup.procs"), str(pid))

    def set_cpu_max(self, cg_path: str, cpu_max: str) -> None:
        _write(os.path.join(cg_path, "cpu.max"), cpu_max)

    def set_memory_max(self, cg_path: str, memory_max: int) -> None:
        _write(os.path.join(cg_path, "memory.max"), str(memory_max))

    def release(self, cg_path: str) -> None:
        cpu_max = os.path.join(cg_path, "cpu.max")
        mem_max = os.path.join(cg_path, "memory.max")
        if os.path.exists(cpu_max):
            _write(cpu_max, "max 100000")
        if os.path.exists(mem_max):
            _write(mem_max, "max")
