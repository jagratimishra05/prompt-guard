import asyncio

import pytest

from backend.app.schemas import Decision, DetectorStatus
from backend.app.services.scan_service import ScanService


UNSET = object()


def rules(prediction="benign"):
    return {
        "is_suspicious": prediction == "malicious",
        "risk_score": 0.8 if prediction == "malicious" else 0.0,
        "risk_level": "high" if prediction == "malicious" else "low",
        "matched_rules": ["instruction_override"] if prediction == "malicious" else [],
        "message": "Rules classified the content.",
    }


def ml(prediction="benign", probability=None):
    if probability is None:
        probability = 0.9 if prediction == "malicious" else 0.1
    return {
        "prediction": prediction,
        "probability": probability,
        "message": "ML classified the content.",
    }


def contextual(status="skipped", prediction=None):
    return {
        "status": status,
        "prediction": prediction,
        "reason": (
            "Contextual analysis is disabled."
            if status == "skipped"
            else "Contextual analysis completed."
        ),
        "provider": "horizon",
    }


def router(*, contextual_enabled=False):
    def route(content, rule_result=None, **kwargs):
        return {
            "detectors": {
                "rule": rule_result is None,
                "ml": rule_result is not None,
                "contextual": contextual_enabled and rule_result is not None,
            },
            "next_step": "run_rule" if rule_result is None else "run_ml",
            "reason": "test routing",
        }
    return route


def run(service, text="Explain queues."):
    return asyncio.run(service.scan(text))


def real_service(
    *,
    rule_result=UNSET,
    ml_result=UNSET,
    contextual_result=UNSET,
    contextual_enabled=False,
    router_result=UNSET,
    risk_result=UNSET,
):
    return ScanService(
        rule_detector=(lambda text: rules() if rule_result is UNSET else rule_result),
        ml_detector=(lambda text: ml() if ml_result is UNSET else ml_result),
        contextual_detector=(
            lambda text, enabled=False: (
                contextual_result
                if contextual_result is not UNSET
                else contextual()
            )
        ),
        detector_router=(
            router(contextual_enabled=contextual_enabled)
            if router_result is UNSET else router_result
        ),
        risk_assessor=risk_result if risk_result is not UNSET else (
            lambda rule, machine_learning, context: {
                "decision": "ALLOW",
                "risk_score": 10,
                "reason": "Completed benign detectors.",
            }
        ),
        contextual_enabled=contextual_enabled,
        is_temporary_mock=False,
    )


def test_successful_real_pipeline_and_normalization():
    result = run(real_service())

    assert result.decision == Decision.ALLOW
    assert result.detectors.rules.status == DetectorStatus.COMPLETED
    assert result.detectors.rules.prediction.value == "benign"
    assert result.detectors.ml.status == DetectorStatus.COMPLETED
    assert result.detectors.ml.malicious_probability == 0.1
    assert result.detectors.contextual.status == DetectorStatus.SKIPPED


def test_malicious_rules_and_ml_are_normalized():
    service = real_service(
        rule_result=rules("malicious"),
        ml_result=ml("malicious", 0.95),
        risk_result=lambda rule, machine_learning, context: {
            "decision": "BLOCK",
            "risk_score": 90,
            "reason": "Multiple malicious classifications.",
        },
    )
    result = run(service)

    assert result.decision == Decision.BLOCK
    assert result.detectors.rules.evidence == ["instruction_override"]
    assert result.detectors.ml.prediction.value == "malicious"
    assert result.detectors.ml.malicious_probability == 0.95


def test_contextual_enabled_and_disabled():
    enabled = real_service(
        contextual_enabled=True,
        contextual_result=contextual("completed", "benign"),
    )
    disabled = real_service(contextual_enabled=False)

    enabled_result = run(enabled)
    disabled_result = run(disabled)

    assert enabled_result.detectors.contextual.status == DetectorStatus.COMPLETED
    assert disabled_result.detectors.contextual.status == DetectorStatus.SKIPPED


def test_router_exception_fails_closed():
    def broken_router(*args, **kwargs):
        raise RuntimeError("router unavailable")

    result = run(real_service(router_result=broken_router))

    assert result.decision == Decision.REVIEW
    assert result.detectors.ml.status == DetectorStatus.FAILED


@pytest.mark.parametrize(
    "routing",
    [
        None,
        {},
        {"detectors": {"rule": True, "ml": True}, "next_step": "run_ml"},
        {"detectors": {"rule": True, "ml": True, "contextual": "yes"}, "next_step": "run_ml"},
        {"detectors": {"rule": True, "ml": False, "contextual": False}},
    ],
)
def test_malformed_router_fails_closed(routing):
    result = run(real_service(router_result=lambda *args, **kwargs: routing))
    assert result.decision == Decision.REVIEW
    assert result.detectors.ml.status == DetectorStatus.FAILED


@pytest.mark.parametrize("detector_name", ["rules", "ml", "contextual"])
def test_detector_exceptions_fail_closed(detector_name):
    def failure(text, **kwargs):
        raise RuntimeError("detector unavailable")

    kwargs = (
        {"contextual_result": contextual(), "contextual_enabled": True}
        if detector_name == "contextual"
        else {}
    )
    service = real_service(**kwargs)
    if detector_name == "rules":
        service._rule_detector = failure
    elif detector_name == "ml":
        service._ml_detector = failure
    else:
        service._contextual_detector = failure

    result = run(service)
    assert result.decision == Decision.REVIEW
    assert getattr(result.detectors, {"rules": "rules", "ml": "ml", "contextual": "contextual"}[detector_name]).status == DetectorStatus.FAILED


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {},
        {"is_suspicious": "yes", "risk_score": 0, "risk_level": "low", "matched_rules": [], "message": "bad"},
        {"is_suspicious": False, "risk_score": True, "risk_level": "low", "matched_rules": [], "message": "bad"},
    ],
)
def test_malformed_rules_results_fail_closed(malformed):
    service = real_service(rule_result=malformed)
    result = run(service)
    assert result.decision == Decision.REVIEW
    assert result.detectors.rules.status == DetectorStatus.FAILED


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {},
        {"prediction": "invalid", "probability": 0.1, "message": "bad"},
        {"prediction": "benign", "probability": True, "message": "bad"},
        {"prediction": "benign", "probability": 1.1, "message": "bad"},
    ],
)
def test_malformed_ml_results_fail_closed(malformed):
    result = run(real_service(ml_result=malformed))
    assert result.decision == Decision.REVIEW
    assert result.detectors.ml.status == DetectorStatus.FAILED


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {},
        {"status": "unknown", "prediction": None, "reason": "bad"},
        {"status": "completed", "prediction": None, "reason": "bad"},
    ],
)
def test_malformed_contextual_results_fail_closed(malformed):
    result = run(real_service(contextual_enabled=True, contextual_result=malformed))
    assert result.decision == Decision.REVIEW
    assert result.detectors.contextual.status == DetectorStatus.FAILED


def test_risk_engine_exception_is_review():
    def broken_risk(*args):
        raise RuntimeError("risk engine unavailable")

    result = run(real_service(risk_result=broken_risk))
    assert result.decision == Decision.REVIEW


@pytest.mark.parametrize(
    "invalid_risk",
    [
        None,
        {},
        {"decision": "ALLOW", "risk_score": 101, "reason": "bad"},
        {"decision": "unknown", "risk_score": 50, "reason": "bad"},
        {"decision": "BLOCK", "risk_score": 50.5, "reason": "bad"},
        {"decision": "BLOCK", "risk_score": 80, "reason": " "},
    ],
)
def test_invalid_risk_results_fail_closed(invalid_risk):
    result = run(real_service(risk_result=lambda *args: invalid_risk))
    assert result.decision == Decision.REVIEW


def test_malicious_evidence_preserves_block_when_risk_engine_fails():
    def broken_risk(*args):
        raise RuntimeError("risk engine unavailable")

    result = run(real_service(
        rule_result=rules("malicious"),
        ml_result=ml("malicious"),
        contextual_enabled=True,
        contextual_result=contextual("completed", "malicious"),
        risk_result=broken_risk,
    ))
    assert result.decision == Decision.BLOCK
