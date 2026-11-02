
import pytest

from app.security.contextual_detector import analyze_context


def test_disabled_contextual_analysis_is_skipped():
    result = analyze_context("Summarize this document.")

    assert result["status"] == "skipped"
    assert result["prediction"] is None


def test_enabled_contextual_analysis_uses_horizon():
    result = analyze_context(
        "Summarize this document.",
        enabled=True,
    )

    assert result["status"] == "completed"
    assert result["prediction"] in {"malicious", "benign"}
    assert result["provider"] == "horizon"
    assert isinstance(result["score"], float)


def test_empty_content_is_rejected():
    with pytest.raises(ValueError):
        analyze_context(" ")


def test_non_string_content_is_rejected():
    with pytest.raises(TypeError):
        analyze_context(None)
