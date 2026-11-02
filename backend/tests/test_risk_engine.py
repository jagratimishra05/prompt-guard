import pytest

from app.security.risk_engine import assess_risk


def make_result(status="completed", prediction="benign", **extra):
    return {
        "status": status,
        "prediction": prediction,
        **extra,
    }


def test_benign_results_allow():
    result = assess_risk(
        make_result(),
        make_result(),
        make_result(status="skipped", prediction=None),
    )

    assert result["decision"] == "ALLOW"
    assert 0 <= result["risk_score"] <= 29


def test_multiple_malicious_results_block():
    result = assess_risk(
        make_result(
            prediction="malicious",
            evidence=["instruction_override"],
        ),
        make_result(
            prediction="malicious",
            malicious_probability=0.95,
        ),
        make_result(prediction="malicious"),
    )

    assert result["decision"] == "BLOCK"
    assert result["risk_score"] >= 70


def test_failed_ml_does_not_allow():
    result = assess_risk(
        make_result(),
        make_result(status="failed", prediction=None),
        make_result(status="skipped", prediction=None),
    )

    assert result["decision"] == "REVIEW"


def test_conflicting_predictions_require_review():
    result = assess_risk(
        make_result(prediction="malicious"),
        make_result(
            prediction="benign",
            malicious_probability=0.10,
        ),
        make_result(status="skipped", prediction=None),
    )

    assert result["decision"] == "REVIEW"


def test_probability_must_be_between_zero_and_one():
    with pytest.raises(ValueError):
        assess_risk(
            make_result(),
            make_result(malicious_probability=1.5),
            make_result(status="skipped", prediction=None),
        )
