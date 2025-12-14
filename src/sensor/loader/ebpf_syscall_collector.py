from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Deque, Dict, List
from uuid import uuid4

from src.sensor.ebpf.loader.bpf_loader import SyscallBpfLoader


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class EbpfSyscallCollector:
    """
    Reads events from SyscallBpfLoader (JSON lines) and converts to the shared CSV schema.
    """
    def __init__(self, buffer_size: int = 5000):
        self.loader = SyscallBpfLoader()
        self.buffer: Deque[Dict] = deque(maxlen=buffer_size)

    def start(self) -> None:
        self.loader.start()

    def stop(self) -> None:
        self.loader.stop()

    def to_event_row(self, raw: Dict) -> Dict:
        # raw example:
        # {"ts_ns":..., "pid":..., "ppid":..., "uid":..., "gid":..., "comm":"bash","filename":"/bin/ls","syscall":"execve"}
        return {
            "timestamp": _now_iso_utc(),
            "event_id": uuid4().hex,
            "event_type": "syscall",

            "pid": int(raw.get("pid") or 0),
            "ppid": int(raw.get("ppid") or 0),
            "uid": int(raw.get("uid") or 0),
            "gid": int(raw.get("gid") or 0),

            "comm": str(raw.get("comm") or ""),
            "exe_path": str(raw.get("filename") or ""),

            "syscall_nr": "",
            "syscall_name": str(raw.get("syscall") or ""),
            "syscall_ret": "",

            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
            "protocol": "",
            "bytes_sent": "",
            "bytes_recv": "",

            "file_path": "",
            "file_op": "",
            "file_flags": "",

            "cpu_percent": "",
            "memory_bytes": "",
            "io_read_bytes": "",
            "io_write_bytes": "",

            "label": "",
            "label_reason": "",
        }

    def latest(self, limit: int = 50) -> List[Dict]:
        items = list(self.buffer)
        return items[-limit:]
