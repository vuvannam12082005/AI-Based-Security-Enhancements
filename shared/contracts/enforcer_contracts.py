from pydantic import BaseModel
from typing import Optional

class EnforcerActionRequest(BaseModel):
    pid: int
    action: str                    # "throttle" | "kill"
    cpu_max: Optional[str] = None  # "quota period" e.g. "20000 100000"
    memory_max: Optional[int] = None

class EnforcerReleaseRequest(BaseModel):
    pid: int
