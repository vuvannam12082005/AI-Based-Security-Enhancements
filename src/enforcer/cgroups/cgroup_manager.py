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
        """
        Best-effort:
        - enable cpu/memory controllers in root subtree_control (if possible)
        - create base cgroup folder
        - enable cpu/memory controllers for base subtree_control (if possible)
        """
        # Enable controllers at root
        try:
            root_ctrl = os.path.join(self.mount, "cgroup.controllers")
            root_sub = os.path.join(self.mount, "cgroup.subtree_control")
            if os.path.exists(root_ctrl) and os.path.exists(root_sub):
                with open(root_ctrl, "r", encoding="utf-8") as f:
                    ctrls = f.read().strip().split()
                want = [c for c in ("cpu", "memory") if c in ctrls]
                if want:
                    _write(root_sub, " ".join([f"+{c}" for c in want]))
        except Exception:
            pass

        os.makedirs(self.base_path, exist_ok=True)

        # Enable controllers at base (so children can use cpu/memory)
        try:
            base_ctrl = os.path.join(self.base_path, "cgroup.controllers")
            base_sub = os.path.join(self.base_path, "cgroup.subtree_control")
            if os.path.exists(base_ctrl) and os.path.exists(base_sub):
                with open(base_ctrl, "r", encoding="utf-8") as f:
                    ctrls = f.read().strip().split()
                want = [c for c in ("cpu", "memory", "pids", "io") if c in ctrls]
                if want:
                    _write(base_sub, " ".join([f"+{c}" for c in want]))
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
