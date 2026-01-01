"""
ML Service for Intrusion Detection System
==========================================
Provides REST API for:
- Model status checking
- Single event prediction
- Batch prediction
- Model retraining
"""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.ml.inference.predictor import Predictor
from src.ml.training.train_pipeline import train_from_csv, get_feature_columns

app = FastAPI(title="ML Intrusion Detection Service", version="1.0")

predictor: Optional[Predictor] = None


# =============================================================================
# REQUEST/RESPONSE SCHEMAS
# =============================================================================

class PredictRequest(BaseModel):
    event: Dict[str, Any]


class PredictBatchRequest(BaseModel):
    events: List[Dict[str, Any]]


class RetrainRequest(BaseModel):
    csv_path: str = "data/synthetic/synthetic_events.csv"
    n_normal: int = 3000
    n_attack: int = 1000
    regenerate: bool = False  # If True, regenerate synthetic data before training


class GenerateDataRequest(BaseModel):
    n_normal: int = 3000
    n_attack: int = 1000
    output_path: str = "data/synthetic/synthetic_events.csv"


# =============================================================================
# LIFECYCLE
# =============================================================================

@app.on_event("startup")
def _load_model() -> None:
    """Load model on startup if exists."""
    global predictor
    try:
        predictor = Predictor("data/models/classifier_pipeline.joblib")
        print("[ML Service] Model loaded successfully")
    except FileNotFoundError:
        print("[ML Service] No model found. Please train first via /ml/retrain")
        predictor = None
    except Exception as e:
        print(f"[ML Service] Error loading model: {e}")
        predictor = None


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/ml/status")
def status() -> Dict[str, Any]:
    """Check ML service status and model readiness."""
    feature_names = []
    if predictor is not None:
        feature_names = predictor.feature_names
    
    return {
        "ready": predictor is not None,
        "model_path": "data/models/classifier_pipeline.joblib",
        "feature_count": len(feature_names),
        "features": feature_names,
        "supported_threats": [
            "sensitive_file_access",
            "privilege_escalation", 
            "suspicious_exec",
            "crypto_miner",
            "reverse_shell",
            "data_exfiltration",
        ],
    }


@app.post("/ml/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    """
    Predict on a single event.
    
    Returns:
        - ok: bool
        - label: 0 (normal) or 1 (attack)
        - score: probability of attack (0.0 - 1.0)
        - action: "allow", "monitor", or "block"
        - threat_type: type of detected threat (if any)
    """
    if predictor is None:
        return {
            "ok": False, 
            "error": "Model not loaded. Train first via POST /ml/retrain",
            "label": 0,
            "score": 0.0,
            "action": "allow",
        }
    
    try:
        result = predictor.predict_one(req.event)
        return result
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "label": 0,
            "score": 0.0,
            "action": "allow",
        }


@app.post("/ml/predict/batch")
def predict_batch(req: PredictBatchRequest) -> Dict[str, Any]:
    """Predict on multiple events."""
    if predictor is None:
        return {"ok": False, "error": "Model not loaded. Train first via POST /ml/retrain"}
    
    try:
        return predictor.predict_batch(req.events)
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/ml/generate")
def generate_data(req: GenerateDataRequest) -> Dict[str, Any]:
    """Generate synthetic training data."""
    try:
        from src.ml.data_generator.synthetic_generator import save_synthetic_csv
        
        path = save_synthetic_csv(
            path=req.output_path,
            n_normal=req.n_normal,
            n_attack=req.n_attack,
        )
        
        return {
            "ok": True,
            "message": f"Generated synthetic data",
            "path": path,
            "n_normal": req.n_normal,
            "n_attack": req.n_attack,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ml/retrain")
def retrain(req: RetrainRequest) -> Dict[str, Any]:
    """
    Retrain the model.
    
    If regenerate=True, will first generate new synthetic data.
    """
    global predictor
    
    try:
        # Optionally regenerate synthetic data
        if req.regenerate:
            from src.ml.data_generator.synthetic_generator import save_synthetic_csv
            save_synthetic_csv(
                path=req.csv_path,
                n_normal=req.n_normal,
                n_attack=req.n_attack,
            )
        
        # Train model
        artifacts, report = train_from_csv(csv_path=req.csv_path)
        
        # Reload predictor with new model
        predictor = Predictor("data/models/classifier_pipeline.joblib")
        
        return {
            "ok": True,
            "message": "Model trained successfully",
            "model_path": artifacts.model_path,
            "report_path": artifacts.report_path,
            "metrics": {
                "accuracy": report["classification_report"]["accuracy"],
                "f1_macro": report["classification_report"]["macro avg"]["f1-score"],
                "precision_attack": report["classification_report"].get("1", {}).get("precision", 0),
                "recall_attack": report["classification_report"].get("1", {}).get("recall", 0),
            },
            "cv_f1_mean": report.get("cv_f1_mean", 0),
            "feature_count": len(artifacts.feature_names),
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=f"Training data not found: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ml/report")
def get_report() -> Dict[str, Any]:
    """Get the latest training report."""
    import json
    import os
    
    report_path = "data/models/train_report.json"
    
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="No training report found. Train model first.")
    
    with open(report_path, "r") as f:
        report = json.load(f)
    
    return {"ok": True, "report": report}