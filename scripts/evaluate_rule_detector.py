
from pathlib import Path
import json
import sys

import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# --------------------------------------------------
# 1. PATHS
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = ROOT / "data" / "processed"

sys.path.insert(0, str(ROOT))

from backend.app.detectors.rule_detector import detect_prompt_injection


# --------------------------------------------------
# 2. LOAD VALIDATION DATA
# --------------------------------------------------

df = pd.read_csv(DATA_DIR / "clean_validation.csv")

X = df["text"].fillna("").astype(str)
y_true = df["label"].astype(int)


# --------------------------------------------------
# 3. RUN RULE DETECTOR
# --------------------------------------------------

results = []

for prompt in X:

    result = detect_prompt_injection(prompt)

    results.append(result)

y_pred = [
    int(result["is_suspicious"])
    for result in results
]

risk_scores = [
    result["risk_score"]
    for result in results
]


# --------------------------------------------------
# 4. CALCULATE METRICS
# --------------------------------------------------

accuracy = accuracy_score(y_true, y_pred)

precision = precision_score(
    y_true, y_pred, zero_division=0
)

recall = recall_score(
    y_true, y_pred, zero_division=0
)

f1 = f1_score(
    y_true, y_pred, zero_division=0
)

cm = confusion_matrix(
    y_true, y_pred, labels=[0, 1]
)

tn, fp, fn, tp = cm.ravel()

false_positive_rate = (
    fp / (fp + tn) if (fp + tn) else 0
)


# --------------------------------------------------
# 5. DISPLAY RESULTS
# --------------------------------------------------

print("\n========== RULE DETECTOR EVALUATION ==========")

print("Total examples:", len(df))
print(f"Accuracy:            {accuracy:.4f}")
print(f"Precision:           {precision:.4f}")
print(f"Recall:              {recall:.4f}")
print(f"F1 Score:            {f1:.4f}")
print(f"False Positive Rate: {false_positive_rate:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Benign", "Malicious"],
        zero_division=0
    )
)


# --------------------------------------------------
# 6. SAVE PREDICTIONS
# --------------------------------------------------

output_df = df.copy()

output_df["rule_prediction"] = y_pred
output_df["rule_risk_score"] = risk_scores

output_df["matched_rules"] = [
    ", ".join(result["matched_rules"])
    for result in results
]

output_df.to_csv(
    DATA_DIR / "rule_validation_predictions.csv",
    index=False
)


# --------------------------------------------------
# 7. SAVE METRICS
# --------------------------------------------------

metrics = {
    "detector": "Rule-based",
    "dataset": "Validation",
    "total_examples": len(df),
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1,
    "false_positive_rate": false_positive_rate,
    "confusion_matrix": cm.tolist(),
    "true_negatives": int(tn),
    "false_positives": int(fp),
    "false_negatives": int(fn),
    "true_positives": int(tp)
}

with open(
    DATA_DIR / "rule_validation_metrics.json",
    "w"
) as file:
    json.dump(metrics, file, indent=4)

print("\nEvaluation files saved successfully.")
