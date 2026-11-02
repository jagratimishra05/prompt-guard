
from typing import Any

from app.security.horizon_detector import detect_prompt_injection


def analyze_context(
    content: str,
    *,
    enabled: bool = False,
) -> dict[str, Any]:
    """
    Run contextual analysis using the Horizon prompt-injection detector.

    When disabled, report skipped.
    When enabled, normalize Horizon's result into PromptGuard's
    standard contextual detector format.
    """

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if not content.strip():
        raise ValueError("content must not be empty")

    if not enabled:
        return {
            "status": "skipped",
            "prediction": None,
            "reason": "Contextual analysis is disabled.",
            "provider": None,
        }

    result = detect_prompt_injection(content)

    # Do not treat failed or unexpected results as benign.
    if (
        result.get("status") != "completed"
        or result.get("prediction") not in {"malicious", "benign"}
    ):
        return {
            "status": "failed",
            "prediction": None,
            "reason": result.get(
                "reason",
                "Horizon contextual analysis did not complete successfully.",
            ),
            "provider": "horizon",
        }

    return {
        "status": "completed",
        "prediction": result["prediction"],
        "reason": result.get(
            "reason",
            "Classification returned by the Horizon model.",
        ),
        "provider": "horizon",
        "score": result.get("score"),
        "model_label": result.get("model_label"),
    }
