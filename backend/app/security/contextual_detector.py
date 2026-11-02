
from typing import Any


def analyze_context(
    content: str,
    *,
    enabled: bool = False,
) -> dict[str, Any]:
    """
    Return a standardized contextual detector result.

    This initial implementation is offline-first. It does not call
    a real LLM. When disabled, it reports that contextual analysis
    was skipped rather than pretending the content is benign.
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

    # No real contextual model is configured in this initial version.
    # Do not fabricate a prediction or claim that a model was called.
    return {
        "status": "skipped",
        "prediction": None,
        "reason": (
            "Contextual analysis was requested, but no real "
            "contextual model provider is configured."
        ),
        "provider": None,
    }
