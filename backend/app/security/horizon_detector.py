
from typing import Any

MODEL_NAME = "Horizon-Labs/prompt-injection-guard-small"

_classifier = None


def _get_classifier():
    """Load the Horizon model only when first needed."""
    global _classifier

    if _classifier is None:
        from transformers import pipeline

        _classifier = pipeline(
            "text-classification",
            model=MODEL_NAME,
        )

    return _classifier


def detect_prompt_injection(content: str) -> dict[str, Any]:
    """Classify content using the Horizon model."""

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if not content.strip():
        raise ValueError("content must not be empty")

    try:
        classifier = _get_classifier()
        result = classifier(content)[0]

        label = str(result["label"]).upper()
        confidence = float(result["score"])

        if label not in {"SAFE", "INJECTION"}:
            return {
                "status": "failed",
                "prediction": None,
                "score": None,
                "reason": "The model returned an unexpected label.",
                "provider": "horizon",
            }

        return {
            "status": "completed",
            "prediction": (
                "malicious" if label == "INJECTION" else "benign"
            ),
            "score": confidence,
            "model_label": label,
            "reason": "Classification returned by the Horizon model.",
            "provider": "horizon",
        }

    except Exception as exc:
        return {
            "status": "failed",
            "prediction": None,
            "score": None,
            "reason": f"Inference failed: {type(exc).__name__}",
            "provider": "horizon",
        }
