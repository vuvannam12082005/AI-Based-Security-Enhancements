from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class SensorStartRequest(BaseModel):
    """Request để start sensor - chỉ hỗ trợ proc mode"""
    mode: str = "proc"  # Chỉ hỗ trợ "proc" mode
    sample_interval: float = 0.5
    auto_detect: bool = False
    auto_action: str = "throttle"  # "kill" | "throttle"


class SensorStatusResponse(BaseModel):
    """Response trả về status của sensor"""
    running: bool
    mode: str
    output_file: Optional[str] = None
    last_event_ts: Optional[float] = None

    auto_detect: bool = False
    auto_action: str = "throttle"

    events_scanned: int = 0
    threats_detected: int = 0
    processes_blocked: int = 0


class SensorLatestEventsResponse(BaseModel):
    """Response trả về các events mới nhất"""
    events: List[Dict[str, Any]]
