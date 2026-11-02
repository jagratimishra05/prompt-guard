
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report
)

# --------------------------------------------------
# 1. DEFINE PROJECT PATHS
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = ROOT / "models" / "prompt_guard_tfidf_lr.joblib"
TEST_PATH = ROOT / "data" / "processed" / "clean_test.csv"

OUTPUT_DIR = ROOT / "data" / "processed"

PREDICTIONS_PATH = OUTPUT_DIR / "ml_test_predictions.csv"
METRICS_PATH = OUTPUT_DIR / "ml_test_metrics.json"

# --------------------------------------------------
# 2. LOAD TEST DATA
# --------------------------------------------------

print("Loading test dataset...")

test = pd.read_csv(TEST_PATH)

X_test = test["text"].astype(str)
y_test = test["label"].astype(int)

print("\n========== TEST DATASET INFORMATION ==========")
print(f"Testing examples: {len(test)}")
print("\nTest label distribution:")
print(y_test.value_counts().sort_index())

# --------------------------------------------------
# 3. LOAD TRAINED MODEL
# --------------------------------------------------

print("\nLoading trained ML model...")

model = joblib.load(MODEL_PATH)

# --------------------------------------------------
# 4. GENERATE PREDICTIONS
# --------------------------------------------------

print("\nGenerating predictions...")

y_pred = model.predict(X_test)
y_probability = model.predict_proba(X_test)[:, 1]

# --------------------------------------------------
# 5. CALCULATE METRICS
# --------------------------------------------------

metrics = {
    "accuracy": float(accuracy_score(y_test, y_pred)),
    "precision": float(precision_score(y_test, y_pred, zero_division=0)),
    "recall": float(recall_score(y_test, y_pred, zero_division=0)),
    "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    "roc_auc": float(roc_auc_score(y_test, y_probability)),
    "pr_auc": float(average_precision_score(y_test, y_probability)),
    "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
}

# --------------------------------------------------
# 6. DISPLAY RESULTS
# --------------------------------------------------

print("\n========== TEST PERFORMANCE ==========")

for metric, value in metrics.items():
    if metric != "confusion_matrix":
        print(f"{metric.upper():12}: {value:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["Benign", "Malicious"],
        zero_division=0
    )
)

# --------------------------------------------------
# 7. SAVE PREDICTIONS
# --------------------------------------------------

results = test.copy()

results["predicted_label"] = y_pred
results["malicious_probability"] = y_probability

results.to_csv(PREDICTIONS_PATH, index=False)

# --------------------------------------------------
# 8. SAVE METRICS
# --------------------------------------------------

with open(METRICS_PATH, "w") as file:
    json.dump(metrics, file, indent=4)

print("\n========== EVALUATION COMPLETED ==========")
print(f"Predictions saved at: {PREDICTIONS_PATH}")
print(f"Metrics saved at: {METRICS_PATH}")
