import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class BpfLoaderConfig:
    project_root: Path
    loader_path: Path

    @staticmethod
    def default() -> "BpfLoaderConfig":
        root = Path(__file__).resolve().parents[4]  # repo root
        loader = root / "src" / "sensor" / "ebpf" / "build" / "syscall_loader"
        return BpfLoaderConfig(project_root=root, loader_path=loader)


class SyscallBpfLoader:
    """
    Runs the C loader and yields JSON events from stdout.
    IMPORTANT: needs root. Run Sensor service with sudo in ebpf mode.
    """
    def __init__(self, cfg: Optional[BpfLoaderConfig] = None):
        self.cfg = cfg or BpfLoaderConfig.default()
        self.proc: Optional[subprocess.Popen[str]] = None

    def start(self) -> None:
        if not self.cfg.loader_path.exists():
            raise FileNotFoundError(
                f"Missing loader binary: {self.cfg.loader_path}. Run `make` in src/sensor/ebpf first."
            )

        if self.proc and self.proc.poll() is None:
            return

        cmd = [str(self.cfg.loader_path)]

        # Force line-buffering when stdout is a pipe (very important)
        stdbuf = shutil.which("stdbuf")
        if stdbuf:
            cmd = [stdbuf, "-oL", "-eL", *cmd]

        self.proc = subprocess.Popen(
            cmd,
            cwd=str(self.cfg.project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # gộp stderr vào stdout để dễ debug
            text=True,
            bufsize=1,
        )

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        finally:
            self.proc = None

    def events(self) -> Iterator[dict]:
        if not self.proc or not self.proc.stdout:
            raise RuntimeError("BPF loader not started")
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # ignore non-json noise
                continue
