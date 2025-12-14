from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class SensorStartRequest(BaseModel):
    mode: str = "proc"
    sample_interval: float = 1.0

class SensorStatusResponse(BaseModel):
    running: bool
    mode: str
    output_file: Optional[str] = None
    last_event_ts: Optional[float] = None

class SensorLatestEventsResponse(BaseModel):
    events: List[Dict[str, Any]]
