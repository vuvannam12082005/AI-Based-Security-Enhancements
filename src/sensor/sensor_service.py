import os
import threading, time
from collections import deque
from typing import Optional

from fastapi import FastAPI, HTTPException
from shared.contracts.sensor_contracts import (
    SensorStartRequest, SensorStatusResponse, SensorLatestEventsResponse
)
from src.sensor.exporter.csv_exporter import CsvExporter
from src.sensor.loader.collector import ProcCollector
from src.sensor.loader.ebpf_syscall_collector import EbpfSyscallCollector

app = FastAPI(title="Sensor Service", version="0.1")

_running = False
_mode = "proc"
_thread: Optional[threading.Thread] = None
_exporter: Optional[CsvExporter] = None
_last_event_ts: Optional[float] = None
_buffer = deque(maxlen=500)

_ebpf_collector: Optional[EbpfSyscallCollector] = None


def _runner_proc(sample_interval: float):
    global _running, _last_event_ts, _exporter
    collector = ProcCollector(sample_interval=sample_interval)
    for e in collector.stream():
        if not _running:
            break
        _last_event_ts = e["timestamp"]
        _buffer.append(e)
        if _exporter:
            _exporter.append(e)


def _runner_ebpf():
    global _running, _last_event_ts, _exporter, _ebpf_collector
    c = EbpfSyscallCollector()
    _ebpf_collector = c
    c.start()
    try:
        for raw in c.loader.events():
            if not _running:
                break
            e = c.to_event_row(raw)
            _last_event_ts = e["timestamp"]
            _buffer.append(e)
            if _exporter:
                _exporter.append(e)
    finally:
        try:
            c.stop()
        finally:
            _ebpf_collector = None


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

    if req.mode not in ("proc", "ebpf"):
        raise HTTPException(status_code=400, detail="mode must be 'proc' or 'ebpf'")

    _mode = req.mode
    _exporter = CsvExporter(out_dir="data/raw")
    _running = True

    if _mode == "ebpf":
        # must be root because syscall_loader (libbpf attach) needs privileges
        if os.geteuid() != 0:
            _running = False
            raise HTTPException(status_code=403, detail="ebpf mode requires running sensor service as root (sudo)")
        _thread = threading.Thread(target=_runner_ebpf, daemon=True)
    else:
        _thread = threading.Thread(target=_runner_proc, args=(req.sample_interval,), daemon=True)

    _thread.start()
    return {"ok": True, "mode": _mode, "output_file": _exporter.file_path}


@app.post("/sensor/stop")
def stop():
    global _running, _ebpf_collector
    _running = False

    # proactively stop ebpf loader so the reader thread unblocks
    if _mode == "ebpf" and _ebpf_collector is not None:
        try:
            _ebpf_collector.stop()
        except Exception:
            pass

    time.sleep(0.1)
    return {"ok": True}


@app.get("/sensor/events/latest", response_model=SensorLatestEventsResponse)
def latest(limit: int = 100):
    limit = max(1, min(limit, 500))
    return SensorLatestEventsResponse(events=list(_buffer)[-limit:])
