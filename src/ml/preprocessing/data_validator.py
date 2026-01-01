"""
Data Validator for ML Pipeline
==============================
Validates event data before prediction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Union

import pandas as pd


@dataclass
class ValidationResult:
    ok: bool
    errors: List[str]
    warnings: List[str]


# Required fields for minimal valid event
REQUIRED_FIELDS = ["timestamp", "event_type"]

# Optional but recommended fields
RECOMMENDED_FIELDS = [
    "pid", "ppid", "uid", "gid", "comm", "exe_path",
    "cpu_percent", "memory_bytes"
]


def validate_events(
    events: Union[pd.DataFrame, Dict[str, Any], List[Dict[str, Any]]]
) -> ValidationResult:
    """
    Validate event data for ML prediction.
    
    Args:
        events: Single event dict, list of dicts, or DataFrame
        
    Returns:
        ValidationResult with ok status, errors, and warnings
    """
    errors: List[str] = []
    warnings: List[str] = []
    
    # Convert to DataFrame for consistent processing
    if isinstance(events, dict):
        df = pd.DataFrame([events])
    elif isinstance(events, list):
        if len(events) == 0:
            return ValidationResult(ok=False, errors=["Empty event list"], warnings=[])
        df = pd.DataFrame(events)
    else:
        df = events.copy()
    
    # Check required fields
    missing_required = [f for f in REQUIRED_FIELDS if f not in df.columns]
    if missing_required:
        # Don't fail - just warn, as ML can still work with numeric features
        warnings.append(f"Missing recommended fields: {missing_required}")
    
    # Check for null values in important fields
    for field in ["pid", "cpu_percent", "memory_bytes"]:
        if field in df.columns and df[field].isna().all():
            warnings.append(f"All values null for field: {field}")
    
    # Check event_type values
    if "event_type" in df.columns:
        valid_types = {"syscall", "network", "file", "process"}
        invalid_types = set(df["event_type"].dropna().unique()) - valid_types
        if invalid_types:
            warnings.append(f"Unknown event_type values: {invalid_types}")
    
    # Validation passes if no hard errors
    ok = len(errors) == 0
    
    return ValidationResult(ok=ok, errors=errors, warnings=warnings)
