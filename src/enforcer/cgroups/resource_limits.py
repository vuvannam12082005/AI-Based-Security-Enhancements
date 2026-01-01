from dataclasses import dataclass
from typing import Optional

@dataclass
class ResourceLimits:
    # cgroup v2: cpu.max format: "<quota> <period>" or "max <period>"
    cpu_max: Optional[str] = None
    # cgroup v2: memory.max in bytes or "max"
    memory_max: Optional[int] = None
