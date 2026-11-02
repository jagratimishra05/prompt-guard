"""Risk scoring and security decisions for PromptGuard.

The score is a heuristic assessment from 0 to 100, not a calibrated
probability of prompt injection.
"""

from typing import Any


VALID_STATUSES = {"completed", "skipped", "failed"}
VALID_PREDICTIONS = {"malicious", "benign"}

ALLOW_MAX = 29
REVIEW_MAX = 69


def _validate_result(name: str, result: dict[str, Any]) -> None:
    """Validate the common structure of a detector result."""
    if not isinstance(result, dict):
        raise TypeError(f"{name} result must be a dictionary.")

    status = result.get("status")
    if status not in VALID_STATUSES:
        raise ValueError(
            f"{name} status must be one of {sorted(VALID_STATUSES)}."
        )

    prediction = result.get("prediction")
    if prediction is not None and prediction not in VALID_PREDICTIONS:
        raise ValueError(
            f"{name} prediction must be 'malicious', 'benign', or None."
        )


def _get_decision(risk_score: int) -> str:
    """Map a risk score to the provisional contract thresholds."""
    if risk_score <= ALLOW_MAX:
        return "ALLOW"
    if risk_score <= REVIEW_MAX:
        return "REVIEW"
    return "BLOCK"


def assess_risk(
    rule_result: dict[str, Any],
    ml_result: dict[str, Any],
    contextual_result: dict[str, Any],
) -> dict[str, Any]:
    """Combine detector results into a risk score and decision.

    Initial heuristic:
    - Rule detector says malicious: +50
    - ML detector says malicious: +40
    - Contextual detector says malicious: +40
    - ML malicious probability >= 0.70: at least +30
    - ML malicious probability >= 0.90: at least +40
    - Conflicting completed predictions: add +10 uncertainty
    - Missing, skipped, or failed required results: do not assume benign

    Scores are capped at 100. Unresolved detector failures or missing
    results force REVIEW unless the available evidence already warrants
    BLOCK. These weights are provisional and must be evaluated.
    """
    results = {
        "rules": rule_result,
        "ml": ml_result,
        "contextual": contextual_result,
    }

    for name, result in results.items():
        _validate_result(name, result)

    score = 0
    reasons: list[str] = []
    predictions: list[str] = []
    unresolved = False

    # Rule detector
    if rule_result["status"] == "completed":
        if rule_result.get("prediction") == "malicious":
            score += 50
            reasons.append("Rule detector found suspicious indicators.")
        elif rule_result.get("prediction") == "benign":
            predictions.append("benign")
        else:
            unresolved = True
            reasons.append("Rule detector returned no prediction.")

        evidence = rule_result.get("evidence", [])
        if evidence:
            reasons.append(f"Matched indicators: {', '.join(map(str, evidence))}.")
    else:
        unresolved = True
        reasons.append(f"Rule detector status is {rule_result['status']}.")

    # ML detector
    if ml_result["status"] == "completed":
        ml_prediction = ml_result.get("prediction")
        if ml_prediction == "malicious":
            score += 40
            reasons.append("ML detector classified the content as malicious.")
            predictions.append("malicious")
        elif ml_prediction == "benign":
            predictions.append("benign")
        else:
            unresolved = True
            reasons.append("ML detector returned no prediction.")

        probability = ml_result.get("malicious_probability")
        if probability is not None:
            if (
                isinstance(probability, bool)
                or not isinstance(probability, (int, float))
                or not 0 <= probability <= 1
            ):
                raise ValueError(
                    "malicious_probability must be a number from 0 to 1."
                )

            if probability >= 0.90:
                score = max(score, 40)
                reasons.append("ML malicious probability is at least 0.90.")
            elif probability >= 0.70:
                score = max(score, 30)
                reasons.append("ML malicious probability is at least 0.70.")
    else:
        unresolved = True
        reasons.append(f"ML detector status is {ml_result['status']}.")

    # Contextual detector
    if contextual_result["status"] == "completed":
        contextual_prediction = contextual_result.get("prediction")
        if contextual_prediction == "malicious":
            score += 40
            reasons.append("Contextual detector identified suspicious content.")
            predictions.append("malicious")
        elif contextual_prediction == "benign":
            predictions.append("benign")
        else:
            unresolved = True
            reasons.append("Contextual detector returned no prediction.")
    else:
        # Contextual analysis may be skipped by the router. That is not
        # automatically a failure, but it cannot be treated as benign.
        if contextual_result["status"] == "failed":
            unresolved = True
            reasons.append("Contextual detector failed.")
        elif contextual_result["status"] == "skipped":
            reasons.append("Contextual analysis was skipped.")

    # Conflicting available predictions increase uncertainty.
    if "malicious" in predictions and "benign" in predictions:
        score += 10
        unresolved = True
        reasons.append("Completed detectors disagree.")

    score = min(100, max(0, int(score)))
    decision = _get_decision(score)

    # Fail closed for protected processing: uncertainty must not silently
    # result in ALLOW. Strong malicious evidence can still result in BLOCK.
    if unresolved and decision == "ALLOW":
        decision = "REVIEW"
        reasons.append("The assessment is incomplete or uncertain.")

    if not reasons:
        reasons.append("No strong malicious indicators were reported.")

    return {
        "risk_score": score,
        "decision": decision,
        "reason": " ".join(reasons),
    }
