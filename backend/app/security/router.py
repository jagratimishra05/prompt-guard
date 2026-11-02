from typing import Any


def route_detectors(
    content: str,
    rule_result: dict[str, Any] | None = None,
    *,
    contextual_enabled: bool = False,
) -> dict[str, Any]:
    """
    Select detectors for PromptGuard.

    Stage 1: Run rules first.
    Stage 2: Run ML for additional assessment.
    Stage 3: Optionally run Horizon contextual analysis.

    This function selects detectors; it does not execute them.
    """

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if not content.strip():
        raise ValueError("content must not be empty")

    # The rule detector must run first.
    if rule_result is None:
        return {
            "detectors": {
                "rule": True,
                "ml": False,
                "contextual": False,
            },
            "next_step": "run_rule",
            "reason": "Rule screening must run first.",
        }

    if not isinstance(rule_result, dict):
        raise TypeError("rule_result must be a dictionary")

    status = rule_result.get("status")
    prediction = rule_result.get("prediction")

    # An invalid, failed, or skipped rule result must not
    # be interpreted as evidence that the content is benign.
    if (
        status != "completed"
        or prediction not in {"malicious", "benign"}
    ):
        return {
            "detectors": {
                "rule": False,
                "ml": True,
                "contextual": contextual_enabled,
            },
            "next_step": "run_ml",
            "reason": (
                "Rule screening is incomplete or uncertain. "
                "Run additional detectors and preserve uncertainty."
            ),
        }

    # Continue to ML even when the rule detector says benign.
    # This avoids relying on rules alone to detect attacks.
    if prediction == "malicious":
        reason = (
            "Rule detector identified suspicious content. "
            "Run ML and any enabled contextual analysis."
        )
    else:
        reason = (
            "Rule detector found no suspicious indicators. "
            "Run ML because a benign rule result does not guarantee safety."
        )

    return {
        "detectors": {
            "rule": False,
            "ml": True,
            "contextual": contextual_enabled,
        },
        "next_step": "run_ml",
        "reason": reason,
    }