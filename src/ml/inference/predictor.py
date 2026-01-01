"""
Predictor for Intrusion Detection Model
========================================
Loads trained model and makes predictions on new events.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import joblib
import pandas as pd

from src.ml.preprocessing.data_validator import validate_events
from src.ml.training.train_pipeline import engineer_features, get_feature_columns


class Predictor:
    """Intrusion detection predictor."""
    
    def __init__(self, model_path: str = "data/models/classifier_pipeline.joblib"):
        self.model_path = model_path
        artifact = joblib.load(model_path)
        
        # Handle both old format (just model) and new format (dict with model + feature_names)
        if isinstance(artifact, dict):
            self.model = artifact["model"]
            self.feature_names = artifact.get("feature_names", get_feature_columns())
        else:
            self.model = artifact
            self.feature_names = get_feature_columns()
    
    def _prepare_event_df(self, event: Dict[str, Any]) -> pd.DataFrame:
        """
        Prepare a single event for prediction.
        Applies feature engineering and ensures correct column order.
        """
        # Create DataFrame from event
        df = pd.DataFrame([event])
        
        # Apply feature engineering
        df = engineer_features(df)
        
        # Ensure all feature columns exist
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
        
        return df[self.feature_names]
    
    def predict_one(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict on a single event.
        
        Returns:
            Dict with ok, label, score, action, threat_type, and warnings
        """
        # Validate event
        vr = validate_events(event)
        if not vr.ok:
            return {"ok": False, "errors": vr.errors, "warnings": vr.warnings}
        
        # Prepare features
        df = self._prepare_event_df(event)
        
        # Get prediction and probability
        label = int(self.model.predict(df)[0])
        
        score: Optional[float] = None
        if hasattr(self.model, "predict_proba"):
            try:
                score = float(self.model.predict_proba(df)[0][1])
            except Exception:
                score = None
        
        # Determine action based on score thresholds
        action = "allow"
        if score is not None:
            if score >= 0.80:
                action = "block"
            elif score >= 0.50:
                action = "monitor"
        elif label == 1:
            action = "block"
        
        # Determine threat type based on features
        threat_type = self._determine_threat_type(event, df)
        
        return {
            "ok": True,
            "label": label,
            "score": score,
            "action": action,
            "threat_type": threat_type,
            "model_path": self.model_path,
            "warnings": vr.warnings,
        }
    
    def _determine_threat_type(self, event: Dict[str, Any], df: pd.DataFrame) -> Optional[str]:
        """Determine the type of threat based on event characteristics."""
        # Check derived features
        if df["is_sensitive_file"].iloc[0] == 1:
            return "sensitive_file_access"
        if df["is_priv_escalation"].iloc[0] == 1:
            return "privilege_escalation"
        if df["is_suspicious_exec"].iloc[0] == 1:
            return "suspicious_exec"
        if df["is_shell_network"].iloc[0] == 1:
            return "reverse_shell"
        if df["is_high_cpu"].iloc[0] == 1 or df["is_miner_name"].iloc[0] == 1:
            return "crypto_miner"
        if df["is_large_outbound"].iloc[0] == 1:
            return "data_exfiltration"
        if df["is_suspicious_port"].iloc[0] == 1:
            return "suspicious_network"
        
        return None
    
    def predict_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Predict on multiple events."""
        results = [self.predict_one(e) for e in events]
        ok = all(r.get("ok") for r in results)
        return {"ok": ok, "results": results}