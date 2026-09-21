# ml/website_model.py
"""
Train the Website Threat Detection model.

Loads datasets/phishing_dataset.csv, extracts URL features,
trains a Random Forest, prints metrics, and saves the model.
"""

from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

sys.path.append(str(Path(__file__).resolve().parent.parent))
from ml.feature_extraction import extract_url_features

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET = BASE_DIR / "datasets" / "phishing_dataset.csv"
MODEL_OUT = BASE_DIR / "ml" / "models" / "website_model.joblib"


def load_dataset():
    df = pd.read_csv(DATASET)
    X, y = [], []
    for _, row in df.iterrows():
        X.append(extract_url_features(str(row["url"])))
        y.append(int(row["label"]))
    return X, y


def train():
    print("=" * 55)
    print("WEBSITE THREAT DETECTION — TRAINING")
    print("=" * 55)

    X, y = load_dataset()
    print(f"Loaded {len(X)} URLs | features per URL = {len(X[0])}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\n--- Evaluation ---")
    print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"F1 Score : {f1_score(y_test, y_pred, zero_division=0):.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT)
    print(f"\n✅ Model saved to: {MODEL_OUT}")


if __name__ == "__main__":
    train()