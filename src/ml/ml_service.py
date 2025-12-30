from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from src.ml.inference.predictor import Predictor
from src.ml.training.train_pipeline import train_from_csv

app = FastAPI(title="ML Service (B)")

predictor: Optional[Predictor] = None


# --------- Request Schemas ---------
class PredictRequest(BaseModel):
    event: Dict[str, Any]


class PredictBatchRequest(BaseModel):
    events: List[Dict[str, Any]]


class RetrainRequest(BaseModel):
    csv_path: str = "data/synthetic/synthetic_events.csv"


# --------- Lifecycle ---------
@app.on_event("startup")
def _load_model() -> None:
    """
    Load model if exists; if not, service still starts but /ml/predict will ask you to retrain.
    """
    global predictor
    try:
        predictor = Predictor("data/models/classifier_pipeline.joblib")
    except Exception:
        predictor = None


# --------- Endpoints ---------
@app.get("/ml/status")
def status() -> Dict[str, Any]:
    return {
        "ready": predictor is not None,
        "model_path": "data/models/classifier_pipeline.joblib",
    }


@app.post("/ml/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    if predictor is None:
        return {"ok": False, "error": "Model not loaded. Train first via /ml/retrain."}
    return predictor.predict_one(req.event)


@app.post("/ml/predict/batch")
def predict_batch(req: PredictBatchRequest) -> Dict[str, Any]:
    if predictor is None:
        return {"ok": False, "error": "Model not loaded. Train first via /ml/retrain."}
    return predictor.predict_batch(req.events)


@app.post("/ml/retrain")
def retrain(req: RetrainRequest) -> Dict[str, Any]:
    """
    Retrain from a CSV (default: synthetic csv). Overwrites model at data/models/classifier_pipeline.joblib
    """
    global predictor
    artifacts, report = train_from_csv(csv_path=req.csv_path)
    predictor = Predictor("data/models/classifier_pipeline.joblib")
    return {"ok": True, "artifacts": artifacts.__dict__, "report": report}
