from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Tuple

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier

from src.ml.preprocessing.data_validator import validate_events


@dataclass
class TrainArtifacts:
    model_path: str
    report_path: str


def train_from_csv(
    csv_path: str = "data/synthetic/synthetic_events.csv",
    model_dir: str = "data/models",
) -> Tuple[TrainArtifacts, Dict]:
    df = pd.read_csv(csv_path)

    vr = validate_events(df)
    if not vr.ok:
        raise ValueError("Schema validation failed: " + "; ".join(vr.errors))

    if "label" not in df.columns:
        raise ValueError("Training requires 'label' column (0 normal, 1 attack).")

    y = df["label"].astype(int)
    X = df.drop(columns=["label", "label_reason"], errors="ignore")

    cat_cols = [c for c in X.columns if X[c].dtype == "object"]
    num_cols = [c for c in X.columns if c not in cat_cols]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                num_cols,
            ),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("ohe", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                cat_cols,
            ),
        ],
        remainder="drop",
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = Pipeline(steps=[("preprocessor", preprocessor), ("model", model)])
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    report = classification_report(y_test, preds, output_dict=True)

    model_path = f"{model_dir}/classifier_pipeline.joblib"
    report_path = f"{model_dir}/train_report.json"

    joblib.dump(clf, model_path)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    artifacts = TrainArtifacts(model_path=model_path, report_path=report_path)
    return artifacts, report


if __name__ == "__main__":
    artifacts, report = train_from_csv()
    print("Saved:", artifacts)
    print("F1 (macro):", report.get("macro avg", {}).get("f1-score"))
