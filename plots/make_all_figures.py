"""
Generate Fig 2 (metrics) as TWO separate charts — one per model.
Uses 5-fold cross-validation for honest mean + std reporting.
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE))

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score)

from ml.feature_extraction import extract_url_features

PLOTS = BASE / "plots"
PLOTS.mkdir(exist_ok=True)

# ============================================================
# URL MODEL — 5-fold cross-validation
# ============================================================
print("Extracting URL features (sampling 20k rows for speed)...")
df_url = pd.read_csv(BASE / "datasets" / "phishing_dataset.csv").sample(20000, random_state=42)
X_url = np.array([extract_url_features(u) for u in df_url["url"]])
y_url = df_url["label"].values

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
url_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

url_scores = {
    "Accuracy":  cross_val_score(url_model, X_url, y_url, cv=cv, scoring="accuracy"),
    "Precision": cross_val_score(url_model, X_url, y_url, cv=cv, scoring="precision"),
    "Recall":    cross_val_score(url_model, X_url, y_url, cv=cv, scoring="recall"),
    "F1-Score":  cross_val_score(url_model, X_url, y_url, cv=cv, scoring="f1"),
}

print("\nURL Model — 5-fold CV results:")
for k, v in url_scores.items():
    print(f"  {k}: mean={v.mean()*100:.2f}%  std={v.std()*100:.2f}%")

# ============================================================
# PE MODEL — 5-fold cross-validation
# ============================================================
print("\nLoading PE dataset...")
PE_FEATS = ["Size_Of_Code_Bytes", "Major_Linker_Version", "Entropy_Score",
            "Number_Of_Sections", "Suspicious_Imports_Count",
            "Is_Digital_Signed", "Debug_Data_Size"]
df_pe = pd.read_csv(BASE / "datasets" / "malware_dataset.csv")
X_pe = df_pe[PE_FEATS].values
y_pe = df_pe["Malicious_Target"].values

pe_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)

pe_scores = {
    "Accuracy":  cross_val_score(pe_model, X_pe, y_pe, cv=cv, scoring="accuracy"),
    "Precision": cross_val_score(pe_model, X_pe, y_pe, cv=cv, scoring="precision"),
    "Recall":    cross_val_score(pe_model, X_pe, y_pe, cv=cv, scoring="recall"),
    "F1-Score":  cross_val_score(pe_model, X_pe, y_pe, cv=cv, scoring="f1"),
}

print("\nPE Model — 5-fold CV results:")
for k, v in pe_scores.items():
    print(f"  {k}: mean={v.mean()*100:.2f}%  std={v.std()*100:.2f}%")

# ============================================================
# FIG 2a — URL MODEL METRICS
# ============================================================
labels = list(url_scores.keys())
means = [url_scores[k].mean() * 100 for k in labels]
stds = [url_scores[k].std() * 100 for k in labels]

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(labels, means, yerr=stds, capsize=6, color="#1F77B4",
              error_kw=dict(ecolor="black", lw=1.5))
for i, (bar, m) in enumerate(zip(bars, means)):
    ax.text(bar.get_x() + bar.get_width() / 2, m + max(stds) + 1,
            f"{m:.2f}%", ha="center", fontsize=10, fontweight="bold")
ax.set_ylabel("Score (%)")
ax.set_ylim(0, 110)
ax.set_title("Fig. 2(a). 5-Fold CV Metrics — Website (Phishing URL) Model",
             fontsize=11, fontweight="bold")
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(PLOTS / "fig2a_url_metrics.png", dpi=200, bbox_inches="tight")
plt.close()
print("\nSaved fig2a_url_metrics.png")

# ============================================================
# FIG 2b — PE MODEL METRICS
# ============================================================
labels = list(pe_scores.keys())
means = [pe_scores[k].mean() * 100 for k in labels]
stds = [pe_scores[k].std() * 100 for k in labels]

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(labels, means, yerr=stds, capsize=6, color="#2CA02C",
              error_kw=dict(ecolor="black", lw=1.5))
for i, (bar, m) in enumerate(zip(bars, means)):
    ax.text(bar.get_x() + bar.get_width() / 2, m + max(stds) + 1,
            f"{m:.2f}%", ha="center", fontsize=10, fontweight="bold")
ax.set_ylabel("Score (%)")
ax.set_ylim(0, 110)
ax.set_title("Fig. 2(b). 5-Fold CV Metrics — Malware (PE/EXE) Model",
             fontsize=11, fontweight="bold")
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()
plt.savefig(PLOTS / "fig2b_pe_metrics.png", dpi=200, bbox_inches="tight")
plt.close()
print("Saved fig2b_pe_metrics.png")

print("\nDone. Check the plots/ folder.")