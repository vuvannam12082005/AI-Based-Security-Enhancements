import os
import time
from typing import Dict, Iterator
from shared.schemas.event_schema import new_event_base

def _read_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readline().strip()
    except Exception:
        return ""

def _readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except Exception:
        return ""

class ProcCollector:
    def __init__(self, sample_interval: float = 1.0):
        self.sample_interval = sample_interval

    def stream(self) -> Iterator[Dict]:
        while True:
            now = time.time()
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)

                comm = _read_first_line(f"/proc/{pid}/comm")
                exe_path = _readlink(f"/proc/{pid}/exe")

                uid = gid = ppid = 0
                try:
                    with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Uid:"):
                                uid = int(line.split()[1])
                            elif line.startswith("Gid:"):
                                gid = int(line.split()[1])
                            elif line.startswith("PPid:"):
                                ppid = int(line.split()[1])
                except Exception:
                    continue

                e = new_event_base()
                e["timestamp"] = now
                e["event_type"] = "syscall"   # MVP: snapshot process, giữ event_type hợp schema
                e["pid"] = pid
                e["ppid"] = ppid
                e["uid"] = uid
                e["gid"] = gid
                e["comm"] = comm
                e["exe_path"] = exe_path
                yield e

            time.sleep(self.sample_interval)
