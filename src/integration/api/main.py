from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


def _env_url(name: str, default: str) -> str:
    return os.getenv(name, default).rstrip("/")


SENSOR_URL = _env_url("SENSOR_URL", "http://localhost:8001")
ENFORCER_URL = _env_url("ENFORCER_URL", "http://localhost:8002")
ML_URL = _env_url("ML_URL", "http://localhost:8003")


app = FastAPI(title="Integration Orchestrator", version="0.1")


class PipelineProcessRequest(BaseModel):
    """
    Nhận 1 event theo schema chung (dict). Orchestrator sẽ:
    - gọi ML /ml/predict
    - nếu malicious -> gọi Enforcer /enforcer/action
    """

    event: Dict[str, Any] = Field(..., description="Event object (28-column schema as dict)")
    enforce_if_malicious: bool = True
    enforcer_action: str = Field("throttle", description="throttle|kill")
    cpu_max: Optional[str] = Field("20000 100000", description='cgroup cpu.max e.g. "20000 100000"')
    memory_max: Optional[int] = Field(268435456, description="memory limit bytes, e.g. 268435456 = 256MB")


class PipelineProcessResponse(BaseModel):
    ok: bool
    ml_result: Dict[str, Any]
    enforcer_result: Optional[Dict[str, Any]] = None


async def _get_json(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    r = await client.get(url, timeout=5)
    r.raise_for_status()
    return r.json()


async def _post_json(client: httpx.AsyncClient, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    r = await client.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


@app.get("/status")
async def status() -> Dict[str, Any]:
    """
    Health check + kiểm tra nhanh khả năng gọi 3 services.
    """
    async with httpx.AsyncClient() as client:
        sensor_ok = ml_ok = enforcer_ok = False
        sensor_err = ml_err = enforcer_err = None

        try:
            await _get_json(client, f"{SENSOR_URL}/sensor/status")
            sensor_ok = True
        except Exception as e:  # noqa: BLE001
            sensor_err = str(e)

        try:
            await _get_json(client, f"{ML_URL}/ml/status")
            ml_ok = True
        except Exception as e:  # noqa: BLE001
            ml_err = str(e)

        try:
            await _get_json(client, f"{ENFORCER_URL}/enforcer/status")
            enforcer_ok = True
        except Exception as e:  # noqa: BLE001
            enforcer_err = str(e)

    return {
        "ok": True,
        "services": {
            "sensor": {"url": SENSOR_URL, "ok": sensor_ok, "error": sensor_err},
            "ml": {"url": ML_URL, "ok": ml_ok, "error": ml_err},
            "enforcer": {"url": ENFORCER_URL, "ok": enforcer_ok, "error": enforcer_err},
        },
    }


@app.post("/pipeline/process", response_model=PipelineProcessResponse)
async def pipeline_process(req: PipelineProcessRequest) -> PipelineProcessResponse:
    """
    Pipeline: Event -> Predict -> (Action).
    - Nếu ML trả label==1 hoặc action=="block" => coi là malicious.
    """
    if req.enforcer_action not in ("throttle", "kill"):
        raise HTTPException(status_code=400, detail="enforcer_action must be 'throttle' or 'kill'")

    pid = req.event.get("pid")
    if pid is None:
        raise HTTPException(status_code=400, detail="event.pid is required")
    try:
        pid_int = int(pid)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"event.pid must be int-like: {e}")

    async with httpx.AsyncClient() as client:
        # 1) predict
        try:
            ml_result = await _post_json(client, f"{ML_URL}/ml/predict", {"event": req.event})
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=f"ML error: {e.response.text}")
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"Cannot reach ML: {e}")

        if not ml_result.get("ok"):
            return PipelineProcessResponse(ok=False, ml_result=ml_result, enforcer_result=None)

        label = ml_result.get("label")
        action = str(ml_result.get("action") or "")
        is_malicious = (label == 1) or (action.lower() == "block")

        # 2) enforce
        enforcer_result: Optional[Dict[str, Any]] = None
        if req.enforce_if_malicious and is_malicious:
            payload: Dict[str, Any] = {"pid": pid_int, "action": req.enforcer_action}
            if req.enforcer_action == "throttle":
                if req.cpu_max:
                    payload["cpu_max"] = req.cpu_max
                if req.memory_max is not None:
                    payload["memory_max"] = req.memory_max

            try:
                enforcer_result = await _post_json(client, f"{ENFORCER_URL}/enforcer/action", payload)
            except httpx.HTTPStatusError as e:
                raise HTTPException(status_code=502, detail=f"Enforcer error: {e.response.text}")
            except Exception as e:  # noqa: BLE001
                raise HTTPException(status_code=502, detail=f"Cannot reach Enforcer: {e}")

        return PipelineProcessResponse(ok=True, ml_result=ml_result, enforcer_result=enforcer_result)


