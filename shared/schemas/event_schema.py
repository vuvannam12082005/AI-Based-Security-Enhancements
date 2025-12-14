from typing import Dict, List, Any
import time
import uuid

EVENT_COLUMNS: List[str] = [
    "timestamp","event_id","event_type","pid","ppid","uid","gid","comm","exe_path",
    "syscall_nr","syscall_name","syscall_ret",
    "src_ip","dst_ip","src_port","dst_port","protocol","bytes_sent","bytes_recv",
    "file_path","file_op","file_flags",
    "cpu_percent","memory_bytes","io_read_bytes","io_write_bytes",
    "label","label_reason"
]

def new_event_base() -> Dict[str, Any]:
    now = time.time()
    return {
        "timestamp": now,
        "event_id": str(uuid.uuid4()),
        "event_type": "",
        "pid": 0, "ppid": 0, "uid": 0, "gid": 0,
        "comm": "", "exe_path": "",

        "syscall_nr": "", "syscall_name": "", "syscall_ret": "",

        "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0,
        "protocol": "", "bytes_sent": 0, "bytes_recv": 0,

        "file_path": "", "file_op": "", "file_flags": 0,

        "cpu_percent": "", "memory_bytes": "", "io_read_bytes": "", "io_write_bytes": "",

        "label": -1, "label_reason": "",
    }
