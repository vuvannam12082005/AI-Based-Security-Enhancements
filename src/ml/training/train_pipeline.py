"""
Training Pipeline for Intrusion Detection Model
================================================
Trains a classifier to detect security threats based on:
- Behavioral features (CPU, memory, I/O)
- Context features (file paths, syscalls, network)
- Derived features (is_sensitive_file, is_shell_process, etc.)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline


@dataclass
class TrainArtifacts:
    model_path: str
    report_path: str
    feature_names: List[str]


# =============================================================================
# FEATURE DEFINITIONS
# =============================================================================

# Raw numeric features from events
NUMERIC_FEATURES = [
    "pid", "ppid", "uid", "gid",
    "src_port", "dst_port",
    "bytes_sent", "bytes_recv",
    "file_flags",
    "cpu_percent", "memory_bytes",
    "io_read_bytes", "io_write_bytes",
]

# Sensitive paths for detection
SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/",
    "/root/.ssh/", "/root/.bash_history", "/etc/gshadow"
]

# Suspicious execution paths
SUSPICIOUS_EXEC_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"]

# Privilege escalation syscalls
PRIV_ESCALATION_SYSCALLS = ["setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid"]

# Shell commands
SHELL_COMMANDS = ["bash", "sh", "zsh", "dash", "fish", "tcsh", "csh"]

# Known miner process names
MINER_COMMANDS = ["xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "bfgminer"]

# Suspicious ports (common for reverse shells)
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1234, 1337, 9001, 9999, 31337]


# =============================================================================
# FEATURE ENGINEERING
# =============================================================================

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create derived features for intrusion detection.
    These features capture security-relevant patterns.
    """
    df = df.copy()
    
    # 1. Sensitive file access detection
    df["is_sensitive_file"] = df["file_path"].apply(
        lambda x: 1 if any(p in str(x) for p in SENSITIVE_PATHS) else 0
    )
    
    # 2. Suspicious execution path detection
    df["is_suspicious_path"] = df["exe_path"].apply(
        lambda x: 1 if any(p in str(x) for p in SUSPICIOUS_EXEC_PATHS) else 0
    )
    
    # 3. Privilege escalation syscall detection
    df["is_priv_escalation"] = df["syscall_name"].apply(
        lambda x: 1 if str(x) in PRIV_ESCALATION_SYSCALLS else 0
    )
    
    # 4. Shell process detection
    df["is_shell"] = df["comm"].apply(
        lambda x: 1 if str(x) in SHELL_COMMANDS else 0
    )
    
    # 5. Miner process detection
    df["is_miner_name"] = df["comm"].apply(
        lambda x: 1 if str(x).lower() in [m.lower() for m in MINER_COMMANDS] else 0
    )
    
    # 6. High CPU detection (potential miner)
    df["is_high_cpu"] = (df["cpu_percent"] > 70).astype(int)
    
    # 7. Suspicious port detection
    df["is_suspicious_port"] = df["dst_port"].apply(
        lambda x: 1 if x in SUSPICIOUS_PORTS else 0
    )
    
    # 8. Large outbound data detection (exfiltration)
    df["is_large_outbound"] = (df["bytes_sent"] > 500000).astype(int)
    
    # 9. Shell with network activity (reverse shell indicator)
    df["is_shell_network"] = ((df["is_shell"] == 1) & (df["event_type"] == "network")).astype(int)
    
    # 10. Non-root accessing sensitive files
    df["is_nonroot_sensitive"] = ((df["uid"] >= 1000) & (df["is_sensitive_file"] == 1)).astype(int)
    
    # 11. execve syscall detection
    df["is_execve"] = (df["syscall_name"] == "execve").astype(int)
    
    # 12. Execve from suspicious path
    df["is_suspicious_exec"] = ((df["is_execve"] == 1) & (df["is_suspicious_path"] == 1)).astype(int)
    
    return df


def get_feature_columns() -> List[str]:
    """Get all feature column names for model input."""
    derived_features = [
        "is_sensitive_file",
        "is_suspicious_path", 
        "is_priv_escalation",
        "is_shell",
        "is_miner_name",
        "is_high_cpu",
        "is_suspicious_port",
        "is_large_outbound",
        "is_shell_network",
        "is_nonroot_sensitive",
        "is_execve",
        "is_suspicious_exec",
    ]
    return NUMERIC_FEATURES + derived_features


# =============================================================================
# TRAINING FUNCTIONS
# =============================================================================

def prepare_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Prepare features and labels for training."""
    # Engineer features
    df = engineer_features(df)
    
    # Get feature columns
    feature_cols = get_feature_columns()
    
    # Ensure all numeric features exist and are numeric
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    
    X = df[feature_cols]
    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    
    return X, y


def train_from_csv(
    csv_path: str = "data/synthetic/synthetic_events.csv",
    model_dir: str = "data/models",
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[TrainArtifacts, Dict[str, Any]]:
    """
    Train intrusion detection model from CSV data.
    
    Args:
        csv_path: Path to training CSV
        model_dir: Directory to save model artifacts
        test_size: Fraction for test split
        random_state: Random seed for reproducibility
    
    Returns:
        Tuple of (TrainArtifacts, report_dict)
    """
    print(f"Loading data from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    if "label" not in df.columns:
        raise ValueError("Training data must have 'label' column (0=normal, 1=attack)")
    
    print(f"Total samples: {len(df)}")
    print(f"  Normal (0): {len(df[df['label'] == 0])}")
    print(f"  Attack (1): {len(df[df['label'] == 1])}")
    
    # Prepare features
    print("\nEngineering features...")
    X, y = prepare_data(df)
    feature_names = list(X.columns)
    
    print(f"Feature count: {len(feature_names)}")
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    print(f"\nTrain samples: {len(X_train)}")
    print(f"Test samples: {len(X_test)}")
    
    # Create and train model
    print("\nTraining RandomForest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=random_state,
        class_weight="balanced",
        n_jobs=-1,
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    conf_matrix = confusion_matrix(y_test, y_pred).tolist()
    
    # Cross-validation score
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    
    print("\n" + "=" * 50)
    print("CLASSIFICATION REPORT")
    print("=" * 50)
    print(classification_report(y_test, y_pred, zero_division=0))
    
    print("\nCONFUSION MATRIX:")
    print(f"  TN={conf_matrix[0][0]}, FP={conf_matrix[0][1]}")
    print(f"  FN={conf_matrix[1][0]}, TP={conf_matrix[1][1]}")
    
    print(f"\nCross-validation F1 scores: {cv_scores}")
    print(f"Mean CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Feature importance
    feature_importance = dict(zip(feature_names, model.feature_importances_))
    sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
    
    print("\nTOP 10 FEATURE IMPORTANCES:")
    for feat, imp in sorted_features[:10]:
        print(f"  {feat}: {imp:.4f}")
    
    # Save artifacts
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "classifier_pipeline.joblib")
    report_path = os.path.join(model_dir, "train_report.json")
    
    # Save model with feature names
    model_artifact = {
        "model": model,
        "feature_names": feature_names,
    }
    joblib.dump(model_artifact, model_path)
    
    # Save report
    full_report = {
        "classification_report": report,
        "confusion_matrix": conf_matrix,
        "cv_f1_scores": cv_scores.tolist(),
        "cv_f1_mean": float(cv_scores.mean()),
        "feature_importance": feature_importance,
        "feature_names": feature_names,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)
    
    print(f"\nModel saved to: {model_path}")
    print(f"Report saved to: {report_path}")
    
    return TrainArtifacts(
        model_path=model_path,
        report_path=report_path,
        feature_names=feature_names,
    ), full_report


if __name__ == "__main__":
    artifacts, report = train_from_csv()
    print(f"\nF1 Score (macro): {report['classification_report']['macro avg']['f1-score']:.4f}")
