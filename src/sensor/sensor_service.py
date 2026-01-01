"""
Sensor Service for Intrusion Detection System
==============================================
Collects system events via /proc polling or eBPF and provides:
- Real-time event streaming
- Auto-detection with ML integration
- Threat response via Enforcer
"""

import os
import threading
import time
import logging
from collections import deque
from typing import Optional, Dict, Any, Set
from concurrent.futures import ThreadPoolExecutor

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from shared.contracts.sensor_contracts import (
    SensorStartRequest, SensorStatusResponse, SensorLatestEventsResponse
)
from src.sensor.exporter.csv_exporter import CsvExporter
from src.sensor.loader.collector import ProcCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sensor")

app = FastAPI(title="Sensor Service", version="1.0")

# =============================================================================
# CONFIGURATION
# =============================================================================

PROTECTED_COMMS = {"streamlit", "uvicorn", "sudo", "su", "pkexec", "polkitd", "systemd", "sshd", "login", "cron"}

ML_URL = os.getenv("ML_URL", "http://localhost:8003")
ENFORCER_URL = os.getenv("ENFORCER_URL", "http://localhost:8002")

# Detection thresholds (rule-based fallback)
CPU_THRESHOLD = 80.0  # CPU > 80% triggers rule-based detection
MEMORY_THRESHOLD = 500 * 1024 * 1024  # > 500MB

# Suspicious ports (reverse shell, C2)
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 1337, 9001, 9999, 31337, 12345}

# Suspicious paths
SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"]

# Shell commands
SHELL_COMMANDS = {"bash", "sh", "zsh", "dash", "fish", "tcsh", "csh"}

# Kernel threads that should never be killed
KERNEL_THREADS = {
    "systemd", "init", "kthreadd", "kworker", "ksoftirqd", 
    "migration", "watchdog", "rcu_sched", "rcu_bh", "rcu_preempt"
}

# =============================================================================
# STATE
# =============================================================================

_running = False
_mode = "proc"
_thread: Optional[threading.Thread] = None
_exporter: Optional[CsvExporter] = None
_last_event_ts: Optional[float] = None
_buffer: deque = deque(maxlen=1000)
# Thread-safety
_state_lock = threading.Lock()
_inflight_pids: Set[int] = set()
_last_submit_ts: Dict[int, float] = {}
_SUBMIT_COOLDOWN_SEC = 0.5  # Giảm từ 1.0 xuống 0.5 để phát hiện nhanh hơn
_cpu_high_streak: Dict[int, int] = {}
_CPU_STREAK_NEED = 2   # Giảm từ 3 xuống 2 để phát hiện nhanh hơn

# Auto-detect state
_auto_detect = False
_auto_action = "throttle"
_events_scanned = 0
_threats_detected = 0
_processes_blocked = 0
_blocked_pids: Set[int] = set()

# Whitelist: PIDs of our own services
_whitelisted_pids: Dict[int, str] = {}

# Enforcement history
_enforcement_history: list = []
_max_history = 200

# Thread pool for async detection
_executor = ThreadPoolExecutor(max_workers=4)


# =============================================================================
# STARTUP
# =============================================================================

@app.on_event("startup")
def _on_startup():
    """Initialize sensor service."""
    my_pid = os.getpid()
    _whitelist_pid(my_pid, "sensor_service")
    logger.info(f"Sensor service started (PID: {my_pid})")
    logger.info(f"ML URL: {ML_URL}")
    logger.info(f"Enforcer URL: {ENFORCER_URL}")


# =============================================================================
# WHITELIST MANAGEMENT
# =============================================================================

def _whitelist_pid(pid: int, name: str) -> None:
    """Add PID to whitelist."""
    _whitelisted_pids[pid] = name
    logger.info(f"Whitelisted PID {pid} ({name})")


def _unwhitelist_pid(pid: int) -> None:
    """Remove PID from whitelist."""
    if pid in _whitelisted_pids:
        name = _whitelisted_pids.pop(pid)
        logger.info(f"Removed PID {pid} ({name}) from whitelist")


def _is_whitelisted(pid: int, comm: str) -> bool:
    """Check if process should be protected from enforcement."""
    # Protect our own service processes by name
    if comm and comm.strip() in PROTECTED_COMMS:
        return True
    # Own PID
    if pid == os.getpid():
        return True
    
    # Explicitly whitelisted
    if pid in _whitelisted_pids:
        return True
    
    # Kernel threads
    if comm and comm.strip().lower() in KERNEL_THREADS:
        return True
    
    # PID 1 and 2 are always protected
    if pid <= 2:
        return True
    
    return False


# =============================================================================
# HISTORY MANAGEMENT
# =============================================================================

def _add_to_history(entry: Dict[str, Any]) -> None:
    global _enforcement_history
    with _state_lock:
        _enforcement_history.append(entry)
        if len(_enforcement_history) > _max_history:
            _enforcement_history = _enforcement_history[-_max_history:]


# =============================================================================
# AUTO-DETECTION LOGIC
# =============================================================================

def _do_auto_detect(event: Dict[str, Any]) -> None:
    """
    Analyze event for threats using ML and rule-based detection.
    Called asynchronously for each event when auto_detect is enabled.
    """
    global _events_scanned, _threats_detected, _processes_blocked

    # ---------- normalize pid ----------
    pid_raw = event.get("pid")
    if pid_raw is None:
        return
    try:
        pid = int(pid_raw)
    except Exception:
        return

    comm = str(event.get("comm", ""))

    # ---------- claim pid (avoid double-processing) + update scanned ----------
    with _state_lock:
        if _is_whitelisted(pid, comm):
            return
        if pid in _blocked_pids:
            return
        if pid in _inflight_pids:
            return

        _inflight_pids.add(pid)
        _events_scanned += 1

    try:
        # ---------- read event fields ----------
        try:
            cpu_percent = float(event.get("cpu_percent", 0) or 0)
        except Exception:
            cpu_percent = 0.0

        try:
            memory_bytes = int(event.get("memory_bytes", 0) or 0)
        except Exception:
            memory_bytes = 0

        exe_path = str(event.get("exe_path", "") or "")
        file_path = str(event.get("file_path", "") or "")
        syscall_name = str(event.get("syscall_name", "") or "")
        cmdline = str(event.get("cmdline", "") or "")
        dst_port = int(event.get("dst_port", 0) or 0)

        # ---------- detection result ----------
        is_threat = False
        threat_type = None
        detection_method = None
        ml_score = 0.0
        ml_label = 0

        # ===================
        # ML-BASED DETECTION
        # ===================
        try:
            with httpx.Client(timeout=2.0) as client:
                response = client.post(f"{ML_URL}/ml/predict", json={"event": event})

            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    ml_label = int(result.get("label", 0) or 0)
                    ml_score = float(result.get("score", 0) or 0)
                    ml_action = str(result.get("action", "allow") or "allow")
                    ml_threat_type = result.get("threat_type")

                    if ml_score is not None and ml_score >= 0.90:
                        is_threat = True
                        threat_type = ml_threat_type or "ml_detected"
                        detection_method = "ml"
                        logger.info(
                            f"[ML] Threat detected: PID={pid}, comm={comm}, "
                            f"type={threat_type}, score={ml_score:.3f}"
                        )
        except httpx.TimeoutException:
            logger.debug(f"ML timeout for PID {pid}")
        except Exception as e:
            logger.debug(f"ML error for PID {pid}: {e}")

        # ========================
        # RULE-BASED DETECTION
        # ========================
        if not is_threat:
            # High CPU (crypto miner)
            if cpu_percent > CPU_THRESHOLD:
                is_threat = True
                threat_type = "high_cpu_usage"
                detection_method = "rule"
                logger.info(f"[RULE] High CPU: PID={pid}, comm={comm}, cpu={cpu_percent:.1f}%")
            
            # High Memory
            elif memory_bytes > MEMORY_THRESHOLD:
                is_threat = True
                threat_type = "high_memory_usage"
                detection_method = "rule"
                logger.info(f"[RULE] High memory: PID={pid}, comm={comm}, mem={memory_bytes/(1024*1024):.1f}MB")
            
            # Sensitive file access
            elif file_path and any(s in file_path for s in ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh", "/root/.ssh"]):
                is_threat = True
                threat_type = "sensitive_file_access"
                detection_method = "rule"
                logger.info(f"[RULE] Sensitive file: PID={pid}, comm={comm}, file={file_path}")
            
            # Suspicious port (reverse shell)
            elif dst_port in SUSPICIOUS_PORTS:
                is_threat = True
                threat_type = "reverse_shell"
                detection_method = "rule"
                logger.info(f"[RULE] Suspicious port: PID={pid}, comm={comm}, port={dst_port}")
            
            # Data exfiltration - large io_write with network connection
            elif event.get("is_exfiltration") or (
                event.get("has_network") and event.get("io_write_delta", 0) > 10 * 1024 * 1024
            ):
                is_threat = True
                threat_type = "data_exfiltration"
                detection_method = "rule"
                logger.warning(
                    f"[RULE] Data exfiltration: PID={pid}, comm={comm}, "
                    f"io_write_delta={event.get('io_write_delta', 0)}"
                )
            # Shell with network connection
            elif comm in SHELL_COMMANDS and dst_port > 0:
                is_threat = True
                threat_type = "reverse_shell"
                detection_method = "rule"
                logger.info(f"[RULE] Shell with network: PID={pid}, comm={comm}, port={dst_port}")
            
            # Execution from /tmp or /dev/shm (check both exe_path AND cmdline)
            elif any(p in exe_path for p in SUSPICIOUS_PATHS) or any(p in cmdline for p in SUSPICIOUS_PATHS):
                is_threat = True
                threat_type = "suspicious_exec"
                detection_method = "rule"
                logger.info(f"[RULE] Suspicious exec: PID={pid}, comm={comm}, exe={exe_path}, cmdline={cmdline[:50]}")

        # ===================
        # TAKE ACTION
        # ===================
        if is_threat:
            with _state_lock:
                _threats_detected += 1

            history_entry = {
                "timestamp": time.time(),
                "pid": pid,
                "comm": comm,
                "exe_path": exe_path,
                "cmdline": cmdline[:100],  # Thêm cmdline vào history
                "cpu_percent": round(cpu_percent, 1),
                "memory_bytes": memory_bytes,
                "file_path": file_path,
                "syscall_name": syscall_name,
                "dst_port": dst_port,  # Thêm dst_port vào history
                "threat_type": threat_type,
                "detection_method": detection_method,
                "ml_score": round(ml_score, 3),
                "ml_label": ml_label,
                "enforcer_action": _auto_action,
                "status": "pending",
                "error": None,
            }

            success = False

            # Call Enforcer
            try:
                with httpx.Client(timeout=3.0) as client:
                    payload = {
                        "pid": pid,
                        "action": _auto_action,
                    }

                    if _auto_action == "throttle":
                        payload["cpu_max"] = "5000 100000"  # 5% CPU limit
                        payload["memory_max"] = 128 * 1024 * 1024  # 128MB limit

                    response = client.post(
                        f"{ENFORCER_URL}/enforcer/action",
                        json=payload,
                    )

                if response.status_code == 200:
                    success = True
                    history_entry["status"] = "success"
                    logger.warning(
                        f"[ENFORCER] {_auto_action.upper()} PID={pid} ({comm}) - Threat: {threat_type}"
                    )
                else:
                    history_entry["status"] = "failed"
                    history_entry["error"] = response.text[:200]
                    logger.error(f"[ENFORCER] Failed for PID={pid}: {response.text}")

            except httpx.TimeoutException:
                history_entry["status"] = "timeout"
                history_entry["error"] = "Enforcer timeout"
            except Exception as e:
                history_entry["status"] = "error"
                history_entry["error"] = str(e)[:200]

            if success:
                with _state_lock:
                    _processes_blocked += 1
                    _blocked_pids.add(pid)
                    _cpu_high_streak.pop(pid, None)
                    _last_submit_ts.pop(pid, None)

            _add_to_history(history_entry)

    finally:
        # release inflight pid
        with _state_lock:
            _inflight_pids.discard(pid)


# =============================================================================
# EVENT PROCESSING
# =============================================================================

def _process_event(event: Dict[str, Any]) -> None:
    """Process collected event: buffer, export, and optionally detect."""
    global _last_event_ts

    _last_event_ts = event.get("timestamp", time.time())
    _buffer.append(event)

    if _exporter:
        _exporter.append(event)

    if not _auto_detect:
        return

    # ---- Filter + cooldown to avoid ThreadPool backlog ----
    pid = event.get("pid")
    try:
        pid = int(pid)
    except Exception:
        return

    # Get event fields for filtering
    try:
        cpu = float(event.get("cpu_percent", 0) or 0)
    except Exception:
        cpu = 0.0

    try:
        mem = int(event.get("memory_bytes", 0) or 0)
    except Exception:
        mem = 0

    has_sensitive_file = bool(event.get("file_path"))
    exe_path = str(event.get("exe_path", "") or "")
    cmdline = str(event.get("cmdline", "") or "")
    dst_port = int(event.get("dst_port", 0) or 0)
    comm = str(event.get("comm", "") or "")

    # --- CPU streak logic: require sustained high CPU ---
    with _state_lock:
        if cpu > CPU_THRESHOLD:
            _cpu_high_streak[pid] = _cpu_high_streak.get(pid, 0) + 1
        else:
            _cpu_high_streak[pid] = 0

    cpu_sustained = _cpu_high_streak.get(pid, 0) >= _CPU_STREAK_NEED

    # Check suspicious conditions
    has_suspicious_exec = (
        any(p in exe_path for p in SUSPICIOUS_PATHS) or
        any(p in cmdline for p in SUSPICIOUS_PATHS)
    )
    has_suspicious_port = dst_port in SUSPICIOUS_PORTS
    has_shell_network = comm in SHELL_COMMANDS and dst_port > 0

    # criteria: multiple suspicious indicators
    suspicious = (
        cpu_sustained or 
        (mem > MEMORY_THRESHOLD) or 
        has_sensitive_file or
        has_suspicious_exec or
        has_suspicious_port or
        has_shell_network
    )
    if not suspicious:
        return

    now = time.time()
    with _state_lock:
        last = _last_submit_ts.get(pid, 0.0)
        if now - last < _SUBMIT_COOLDOWN_SEC:
            return
        _last_submit_ts[pid] = now

    _executor.submit(_do_auto_detect, event.copy())


def _runner_proc(sample_interval: float):
    """Run /proc-based collection loop."""
    global _running
    collector = ProcCollector(sample_interval=sample_interval)
    
    for event in collector.stream():
        if not _running:
            break
        _process_event(event)


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/sensor/status", response_model=SensorStatusResponse)
def status():
    """Get sensor service status."""
    return SensorStatusResponse(
        running=_running,
        mode=_mode,
        output_file=_exporter.file_path if _exporter else None,
        last_event_ts=_last_event_ts,
        auto_action=_auto_action,
        auto_detect=_auto_detect,
        events_scanned=_events_scanned,
        threats_detected=_threats_detected,
        processes_blocked=_processes_blocked,
    )


@app.post("/sensor/start")
def start(req: SensorStartRequest):
    """Start event collection."""
    global _running, _mode, _thread, _exporter, _auto_detect, _auto_action
    global _events_scanned, _threats_detected, _processes_blocked, _blocked_pids
    
    if _running:
        return {"ok": True, "message": "Already running"}
    
    if req.mode not in ("proc", "ebpf"):
        raise HTTPException(status_code=400, detail="mode must be 'proc' or 'ebpf'")
    
    if req.auto_action not in ("kill", "throttle"):
        raise HTTPException(status_code=400, detail="auto_action must be 'kill' or 'throttle'")
    
    # Reset state
    _mode = req.mode
    _auto_detect = req.auto_detect
    _auto_action = req.auto_action
    _events_scanned = 0
    _threats_detected = 0
    _processes_blocked = 0
    _blocked_pids.clear()
    _cpu_high_streak.clear()
    
    # Initialize exporter
    _exporter = CsvExporter(out_dir="data/raw")
    _running = True
    
    # Start collection thread
    if _mode == "proc":
        _thread = threading.Thread(
            target=_runner_proc, 
            args=(req.sample_interval,), 
            daemon=True
        )
    else:
        if os.geteuid() != 0:
            _running = False
            raise HTTPException(
                status_code=403, 
                detail="eBPF mode requires root privileges"
            )
        raise HTTPException(status_code=501, detail="eBPF mode not yet implemented")
    
    _thread.start()
    
    logger.info(
        f"Sensor started: mode={_mode}, interval={req.sample_interval}s, "
        f"auto_detect={_auto_detect}, action={_auto_action}"
    )
    
    return {
        "ok": True,
        "mode": _mode,
        "output_file": _exporter.file_path,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "sample_interval": req.sample_interval,
    }


@app.post("/sensor/stop")
def stop():
    """Stop event collection."""
    global _running
    
    _running = False
    time.sleep(0.2)
    
    logger.info(
        f"Sensor stopped. Stats: scanned={_events_scanned}, "
        f"threats={_threats_detected}, blocked={_processes_blocked}"
    )
    
    return {
        "ok": True,
        "events_scanned": _events_scanned,
        "threats_detected": _threats_detected,
        "processes_blocked": _processes_blocked,
    }


@app.get("/sensor/events/latest", response_model=SensorLatestEventsResponse)
def get_latest_events(limit: int = 100):
    """Get latest collected events."""
    limit = max(1, min(limit, 1000))
    return SensorLatestEventsResponse(events=list(_buffer)[-limit:])


@app.get("/sensor/stats")
def get_stats():
    """Get detection statistics."""
    return {
        "running": _running,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "events_scanned": _events_scanned,
        "threats_detected": _threats_detected,
        "processes_blocked": _processes_blocked,
        "blocked_pids": list(_blocked_pids),
        "buffer_size": len(_buffer),
    }


# =============================================================================
# WHITELIST ENDPOINTS
# =============================================================================

class WhitelistRequest(BaseModel):
    pid: int
    name: str = "unknown"
    action: str = "add"


@app.get("/sensor/whitelist")
def get_whitelist():
    """Get current whitelist."""
    return {
        "whitelisted_pids": _whitelisted_pids.copy(),
        "kernel_threads": list(KERNEL_THREADS),
        "sensor_pid": os.getpid(),
    }


@app.post("/sensor/whitelist")
def manage_whitelist(req: WhitelistRequest):
    """Add or remove PID from whitelist."""
    if req.action == "add":
        _whitelist_pid(req.pid, req.name)
        return {"ok": True, "action": "added", "pid": req.pid, "name": req.name}
    elif req.action == "remove":
        _unwhitelist_pid(req.pid)
        return {"ok": True, "action": "removed", "pid": req.pid}
    else:
        raise HTTPException(status_code=400, detail="action must be 'add' or 'remove'")


# =============================================================================
# AUTO-DETECT CONTROL
# =============================================================================

class AutoDetectRequest(BaseModel):
    enabled: bool
    action: str = "throttle"


@app.post("/sensor/auto_detect")
def set_auto_detect(req: AutoDetectRequest):
    """Toggle auto-detect at runtime."""
    global _auto_detect, _auto_action
    
    if req.action not in ("kill", "throttle"):
        raise HTTPException(status_code=400, detail="action must be 'kill' or 'throttle'")
    
    old_state = _auto_detect
    _auto_detect = req.enabled
    _auto_action = req.action
    
    status_str = "ENABLED" if _auto_detect else "DISABLED"
    logger.info(f"Auto-detect {status_str} (action: {_auto_action})")
    
    return {
        "ok": True,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "changed": old_state != _auto_detect,
    }


# =============================================================================
# HISTORY ENDPOINT
# =============================================================================

@app.get("/sensor/enforcement_history")
def get_enforcement_history(limit: int = 50):
    """Get history of detected threats and actions."""
    limit = max(1, min(limit, _max_history))
    history = list(reversed(_enforcement_history[-limit:]))
    
    return {
        "ok": True,
        "count": len(history),
        "total": len(_enforcement_history),
        "history": history,
    }


# =============================================================================
# MANUAL DETECTION ENDPOINT
# =============================================================================

@app.post("/sensor/analyze")
def analyze_event(event: Dict[str, Any]):
    """
    Manually analyze a single event without taking action.
    Useful for testing detection logic.
    """
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(
                f"{ML_URL}/ml/predict",
                json={"event": event}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"ok": False, "error": response.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}
