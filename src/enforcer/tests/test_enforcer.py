from fastapi.testclient import TestClient
from src.enforcer.enforcer_service import app

client = TestClient(app)

def test_status():
    r = client.get("/enforcer/status")
    assert r.status_code == 200
    assert r.json().get("ok") is True
