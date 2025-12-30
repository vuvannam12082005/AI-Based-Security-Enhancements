from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import joblib
import pandas as pd

from src.ml.preprocessing.data_validator import validate_events


class Predictor:
    def __init__(self, model_path: str = "data/models/classifier_pipeline.joblib"):
        self.model_path = model_path
        self.pipeline = joblib.load(model_path)

    def predict_one(self, event: Dict[str, Any]) -> Dict[str, Any]:
        vr = validate_events(event)
        if not vr.ok:
            return {"ok": False, "errors": vr.errors, "warnings": vr.warnings}

        df = pd.DataFrame([event])

        # score = probability attack (label=1) if available
        score: Optional[float] = None
        if hasattr(self.pipeline, "predict_proba"):
            try:
                score = float(self.pipeline.predict_proba(df)[0][1])
            except Exception:
                score = None

        label = int(self.pipeline.predict(df)[0])

        # simple action policy
        action = "allow"
        if score is not None:
            if score >= 0.85:
                action = "block"
            elif score >= 0.60:
                action = "monitor"

        return {
            "ok": True,
            "label": label,
            "score": score,
            "action": action,
            "model_path": self.model_path,
            "warnings": vr.warnings,
        }

    def predict_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = [self.predict_one(e) for e in events]
        ok = all(r.get("ok") for r in results)
        return {"ok": ok, "results": results}
