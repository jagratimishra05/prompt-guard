
import os
import json
import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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

# File paths
TRAIN_PATH = "data/processed/clean_train.csv"
VALIDATION_PATH = "data/processed/clean_validation.csv"

MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "prompt_guard_tfidf_lr.joblib")
METRICS_PATH = "data/processed/ml_validation_metrics.json"

# Load datasets
train_df = pd.read_csv(TRAIN_PATH)
validation_df = pd.read_csv(VALIDATION_PATH)

X_train = train_df["text"].fillna("").astype(str)
y_train = train_df["label"].astype(int)

X_val = validation_df["text"].fillna("").astype(str)
y_val = validation_df["label"].astype(int)

print("========== DATASET INFORMATION ==========")
print("Training examples:", len(X_train))
print("Validation examples:", len(X_val))
print("\nTraining label distribution:")
print(y_train.value_counts().sort_index())
print("\nValidation label distribution:")
print(y_val.value_counts().sort_index())

# Build ML pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=50000,
            min_df=2,
            max_df=0.98,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            C=1.0,
            random_state=42
        )
    )
])

# Train model
print("\n========== TRAINING MODEL ==========")
model.fit(X_train, y_train)
print("Training completed.")

# Evaluate on training data to check overfitting
train_predictions = model.predict(X_train)
train_probabilities = model.predict_proba(X_train)[:, 1]

# Evaluate on validation data
val_predictions = model.predict(X_val)
val_probabilities = model.predict_proba(X_val)[:, 1]

# Calculate metrics
metrics = {
    "train": {
        "accuracy": float(accuracy_score(y_train, train_predictions)),
        "precision": float(precision_score(y_train, train_predictions, zero_division=0)),
        "recall": float(recall_score(y_train, train_predictions, zero_division=0)),
        "f1": float(f1_score(y_train, train_predictions, zero_division=0))
    },
    "validation": {
        "accuracy": float(accuracy_score(y_val, val_predictions)),
        "precision": float(precision_score(y_val, val_predictions, zero_division=0)),
        "recall": float(recall_score(y_val, val_predictions, zero_division=0)),
        "f1": float(f1_score(y_val, val_predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_val, val_probabilities)),
        "pr_auc": float(average_precision_score(y_val, val_probabilities)),
        "confusion_matrix": confusion_matrix(y_val, val_predictions).tolist()
    }
}

# Display results
print("\n========== TRAINING PERFORMANCE ==========")
for metric, value in metrics["train"].items():
    print(f"{metric.capitalize():12}: {value:.4f}")

print("\n========== VALIDATION PERFORMANCE ==========")
for metric, value in metrics["validation"].items():
    if metric != "confusion_matrix":
        print(f"{metric.capitalize():12}: {value:.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_val, val_predictions))

print("\nClassification Report:")
print(classification_report(
    y_val,
    val_predictions,
    target_names=["Benign", "Malicious"],
    zero_division=0
))

# Save trained model
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(model, MODEL_PATH)

# Save validation metrics
with open(METRICS_PATH, "w") as file:
    json.dump(metrics, file, indent=4)

print("\n========== SAVING COMPLETED ==========")
print("Model saved at:", MODEL_PATH)
print("Metrics saved at:", METRICS_PATH)
