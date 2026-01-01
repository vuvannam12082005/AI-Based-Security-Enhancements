from fastapi.testclient import TestClient
from src.sensor.sensor_service import app

client = TestClient(app)

def test_sensor_status():
    r = client.get("/sensor/status")
    assert r.status_code == 200
    assert "running" in r.json()

def test_sensor_start_latest_stop():
    r = client.post("/sensor/start", json={"mode":"proc","sample_interval":0.1})
    assert r.status_code == 200
    r2 = client.get("/sensor/events/latest?limit=3")
    assert r2.status_code == 200
    assert "events" in r2.json()
    client.post("/sensor/stop")
