import pandas as pd
from fastapi.testclient import TestClient

from src.ml.ml_service import app
from src.ml.training.train_pipeline import get_feature_columns


def _create_test_event() -> dict:
    """Create a test event with all required fields."""
    return {
        "timestamp": 1700000000.0,
        "event_id": "test-event-001",
        "event_type": "syscall",
        "pid": 1234,
        "ppid": 1000,
        "uid": 1000,
        "gid": 1000,
        "comm": "python3",
        "exe_path": "/usr/bin/python3",
        "syscall_nr": 59,
        "syscall_name": "execve",
        "syscall_ret": 0,
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "file_path": "",
        "file_op": "",
        "file_flags": 0,
        "cpu_percent": 5.0,
        "memory_bytes": 50000000,
        "io_read_bytes": 1000,
        "io_write_bytes": 500,
    }


def _create_attack_event() -> dict:
    """Create an attack event (sensitive file access)."""
    event = _create_test_event()
    event["file_path"] = "/etc/shadow"
    event["file_op"] = "read"
    event["uid"] = 1000  # Non-root accessing sensitive file
    return event


def _ensure_trained(client: TestClient) -> None:
    """Ensure model is trained before tests."""
    # First generate synthetic data
    r = client.post("/ml/retrain", json={
        "csv_path": "data/synthetic/synthetic_events.csv",
        "regenerate": True,
        "n_normal": 500,
        "n_attack": 200
    })
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True


def test_ml_status_format():
    """Test /ml/status endpoint."""
    client = TestClient(app)
    r = client.get("/ml/status")
    assert r.status_code == 200
    body = r.json()
    assert "ready" in body
    assert "model_path" in body
    assert "supported_threats" in body


def test_ml_retrain():
    """Test model training."""
    client = TestClient(app)
    _ensure_trained(client)
    
    r = client.get("/ml/status")
    assert r.status_code == 200
    assert r.json().get("ready") is True


def test_ml_predict_normal_event():
    """Test prediction on normal event."""
    client = TestClient(app)
    _ensure_trained(client)
    
    event = _create_test_event()
    r = client.post("/ml/predict", json={"event": event})
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    assert "label" in body
    assert "score" in body
    assert "action" in body


def test_ml_predict_attack_event():
    """Test prediction on attack event."""
    client = TestClient(app)
    _ensure_trained(client)
    
    event = _create_attack_event()
    r = client.post("/ml/predict", json={"event": event})
    assert r.status_code == 200
    body = r.json()
    assert body.get("ok") is True
    assert "label" in body
    assert "threat_type" in body


def test_ml_predict_batch():
    """Test batch prediction."""
    client = TestClient(app)
    _ensure_trained(client)
    
    events = [_create_test_event(), _create_attack_event()]
    r = client.post("/ml/predict/batch", json={"events": events})
    assert r.status_code == 200
    body = r.json()
    assert "results" in body
    assert len(body["results"]) == 2
