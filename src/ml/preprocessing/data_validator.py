from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Union

import importlib
import pandas as pd


@dataclass
class ValidationResult:
    ok: bool
    errors: List[str]
    warnings: List[str]
    required_fields: List[str]
    categorical_fields: List[str]
    numeric_fields: List[str]


def _detect_pydantic_model_fields() -> Tuple[List[str], List[str], List[str]]:
    fallback_required = ["timestamp", "event_type"]
    fallback_categorical = ["event_type"]
    fallback_numeric: List[str] = []

    try:
        mod = importlib.import_module("shared.schemas.event_schema")
    except Exception:
        return fallback_required, fallback_categorical, fallback_numeric

    try:
        BaseModel = importlib.import_module("pydantic").BaseModel
    except Exception:
        return fallback_required, fallback_categorical, fallback_numeric

    candidates = []
    for attr_name in dir(mod):
        attr = getattr(mod, attr_name)
        try:
            if isinstance(attr, type) and issubclass(attr, BaseModel) and attr is not BaseModel:
                candidates.append(attr)
        except Exception:
            pass

    if not candidates:
        return fallback_required, fallback_categorical, fallback_numeric

    best = max(candidates, key=lambda cls: len(getattr(cls, "model_fields", getattr(cls, "__fields__", {}))))
    fields = getattr(best, "model_fields", None) or getattr(best, "__fields__", None) or {}

    required_fields: List[str] = []
    categorical_fields: List[str] = []
    numeric_fields: List[str] = []

    for fname, finfo in fields.items():
        is_required = False
        try:
            if hasattr(finfo, "is_required"):
                is_required = bool(finfo.is_required())  # pydantic v2
            else:
                is_required = bool(getattr(finfo, "required", False))  # pydantic v1
        except Exception:
            is_required = False

        if is_required:
            required_fields.append(fname)

        ann = getattr(finfo, "annotation", None)
        if ann is None:
            ann = getattr(finfo, "type_", None)

        ann_str = str(ann).lower() if ann is not None else ""
        if any(k in ann_str for k in ["str", "literal", "enum"]):
            categorical_fields.append(fname)
        elif any(k in ann_str for k in ["int", "float", "double", "decimal"]):
            numeric_fields.append(fname)

    if "event_type" not in required_fields:
        required_fields.append("event_type")
    if "event_type" not in categorical_fields:
        categorical_fields.append("event_type")

    def uniq(xs):
        out = []
        seen = set()
        for x in xs:
            if x not in seen:
                out.append(x)
                seen.add(x)
        return out

    return uniq(required_fields), uniq(categorical_fields), uniq(numeric_fields)


def validate_events(events: Union[pd.DataFrame, Dict[str, Any], List[Dict[str, Any]]]) -> ValidationResult:
    required, categorical, numeric = _detect_pydantic_model_fields()
    errors: List[str] = []
    warnings: List[str] = []

    if isinstance(events, dict):
        df = pd.DataFrame([events])
    elif isinstance(events, list):
        df = pd.DataFrame(events)
    else:
        df = events.copy()

    missing = [c for c in required if c not in df.columns]
    if missing:
        errors.append(f"Missing required fields: {missing}")

    if "event_type" in df.columns and df["event_type"].isna().any():
        warnings.append("Some event_type values are null/NaN.")

    ok = len(errors) == 0
    return ValidationResult(
        ok=ok,
        errors=errors,
        warnings=warnings,
        required_fields=required,
        categorical_fields=categorical,
        numeric_fields=numeric,
    )
# --- hard alias to avoid import mismatch ---
__all__ = ["validate_events", "ValidationResult"]

print("[data_validator] loaded OK, has validate_events =", "validate_events" in globals())
