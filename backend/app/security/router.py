
from typing import Any


def route_detectors(
    content: str,
    rule_result: dict[str, Any] | None = None,
    *,
    contextual_enabled: bool = False,
) -> dict[str, Any]:
    """
    Select detectors adaptively.

    Stage 1: Always run the rule detector.
    Stage 2: Run ML when rule evidence indicates suspicion,
             when the rule result is uncertain, or when no
             rule result has been supplied yet.
    Stage 3: Contextual analysis is optional.

    This function selects detectors; it does not execute them.
    """

    if not isinstance(content, str):
        raise TypeError("content must be a string")

    if not content.strip():
        raise ValueError("content must not be empty")

    # No preliminary result means the rule detector must run first.
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
    evidence = rule_result.get("evidence", [])

    # Never assume a failed or skipped rule detector means benign.
    if status != "completed":
        return {
            "detectors": {
                "rule": False,
                "ml": True,
                "contextual": contextual_enabled,
            },
            "next_step": "run_ml",
            "reason": (
                "Rule detector did not complete; use ML as an "
                "additional signal and handle uncertainty safely."
            ),
        }

    if prediction not in {"malicious", "benign"}:
        return {
            "detectors": {
                "rule": False,
                "ml": True,
                "contextual": contextual_enabled,
            },
            "next_step": "run_ml",
            "reason": "Rule result is uncertain; run ML.",
        }

    # Suspicious evidence or a malicious prediction triggers ML.
    if prediction == "malicious" or evidence:
        return {
            "detectors": {
                "rule": False,
                "ml": True,
                "contextual": contextual_enabled,
            },
            "next_step": "run_ml",
            "reason": (
                "Rule detector found suspicious evidence; "
                "run ML for additional assessment."
            ),
        }

    # Fast path: rule detector returned benign with no evidence.
    # This optimization must be evaluated against an all-detectors
    # baseline before being enabled in a production security system.
    return {
        "detectors": {
            "rule": False,
            "ml": False,
            "contextual": False,
        },
        "next_step": "assess_risk",
        "reason": (
            "Rule detector found no suspicious evidence. "
            "Fast path selected; this is not a guarantee of safety."
        ),
    }
