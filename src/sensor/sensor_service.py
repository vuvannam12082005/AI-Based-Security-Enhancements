import threading, time
from collections import deque
from typing import Optional

from fastapi import FastAPI
from shared.contracts.sensor_contracts import (
    SensorStartRequest, SensorStatusResponse, SensorLatestEventsResponse
)
from src.sensor.exporter.csv_exporter import CsvExporter
from src.sensor.loader.collector import ProcCollector

app = FastAPI(title="Sensor Service", version="0.1")

_running = False
_mode = "proc"
_thread: Optional[threading.Thread] = None
_exporter: Optional[CsvExporter] = None
_last_event_ts: Optional[float] = None
_buffer = deque(maxlen=500)

def _runner(sample_interval: float):
    global _running, _last_event_ts, _exporter
    collector = ProcCollector(sample_interval=sample_interval)
    for e in collector.stream():
        if not _running:
            break
        _last_event_ts = e["timestamp"]
        _buffer.append(e)
        if _exporter:
            _exporter.append(e)

@app.get("/sensor/status", response_model=SensorStatusResponse)
def status():
    return SensorStatusResponse(
        running=_running,
        mode=_mode,
        output_file=_exporter.file_path if _exporter else None,
        last_event_ts=_last_event_ts
    )

@app.post("/sensor/start")
def start(req: SensorStartRequest):
    global _running, _mode, _thread, _exporter
    if _running:
        return {"ok": True, "message": "already running"}
    _mode = req.mode
    _exporter = CsvExporter(out_dir="data/raw")
    _running = True
    _thread = threading.Thread(target=_runner, args=(req.sample_interval,), daemon=True)
    _thread.start()
    return {"ok": True, "mode": _mode, "output_file": _exporter.file_path}

@app.post("/sensor/stop")
def stop():
    global _running
    _running = False
    time.sleep(0.1)
    return {"ok": True}

@app.get("/sensor/events/latest", response_model=SensorLatestEventsResponse)
def latest(limit: int = 100):
    limit = max(1, min(limit, 500))
    return SensorLatestEventsResponse(events=list(_buffer)[-limit:])
