"""
Event Schema Definition
=======================
Defines the standard event format for the entire system.
All components (Sensor, ML, Integration) use this schema.
"""

from typing import Dict, List, Any
import time
import uuid


# All columns in the event CSV/dict
EVENT_COLUMNS: List[str] = [
    # Identification
    "timestamp",
    "event_id", 
    "event_type",  # syscall, network, file
    
    # Process info
    "pid",
    "ppid",
    "uid",
    "gid",
    "comm",
    "exe_path",
    
    # Syscall info
    "syscall_nr",
    "syscall_name",
    "syscall_ret",
    
    # Network info
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_recv",
    
    # File info
    "file_path",
    "file_op",
    "file_flags",
    
    # Resource info
    "cpu_percent",
    "memory_bytes",
    "io_read_bytes",
    "io_write_bytes",
    
    # Labels (for training data)
    "label",
    "label_reason",
]


# Valid event types
EVENT_TYPES = {"syscall", "network", "file", "process"}

# Valid file operations
FILE_OPERATIONS = {"read", "write", "open", "close", "create", "delete", "rename"}

# Valid network protocols
NETWORK_PROTOCOLS = {"TCP", "UDP", "ICMP", ""}


def new_event_base() -> Dict[str, Any]:
    """
    Create a new event with default values.
    All fields are initialized to safe defaults.
    """
    now = time.time()
    return {
        # Identification
        "timestamp": now,
        "event_id": str(uuid.uuid4()),
        "event_type": "syscall",
        
        # Process info
        "pid": 0,
        "ppid": 0,
        "uid": 0,
        "gid": 0,
        "comm": "",
        "exe_path": "",
        
        # Syscall info
        "syscall_nr": 0,
        "syscall_name": "",
        "syscall_ret": 0,
        
        # Network info
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "",
        "bytes_sent": 0,
        "bytes_recv": 0,
        
        # File info
        "file_path": "",
        "file_op": "",
        "file_flags": 0,
        
        # Resource info
        "cpu_percent": 0.0,
        "memory_bytes": 0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
        
        # Labels
        "label": -1,  # -1 = unlabeled, 0 = normal, 1 = attack
        "label_reason": "",
    }


def validate_event(event: Dict[str, Any]) -> tuple:
    """
    Validate an event dict.
    
    Returns:
        (is_valid, errors)
    """
    errors = []
    
    # Check required fields
    if "timestamp" not in event:
        errors.append("Missing timestamp")
    
    if "event_type" not in event:
        errors.append("Missing event_type")
    elif event["event_type"] not in EVENT_TYPES:
        errors.append(f"Invalid event_type: {event['event_type']}")
    
    # Validate numeric fields
    for field in ["pid", "ppid", "uid", "gid"]:
        if field in event and event[field] is not None:
            try:
                int(event[field])
            except (ValueError, TypeError):
                errors.append(f"Invalid {field}: must be integer")
    
    return len(errors) == 0, errors
