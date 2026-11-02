
import pytest

from app.security.contextual_detector import analyze_context


def test_disabled_contextual_analysis_is_skipped():
    result = analyze_context("Summarize this document.")

    assert result["status"] == "skipped"
    assert result["prediction"] is None


def test_enabled_without_provider_is_not_fabricated():
    result = analyze_context(
        "Summarize this document.",
        enabled=True,
    )

    assert result["status"] == "skipped"
    assert result["prediction"] is None
    assert "no real" in result["reason"].lower()


def test_empty_content_is_rejected():
    with pytest.raises(ValueError):
        analyze_context(" ")


def test_non_string_content_is_rejected():
    with pytest.raises(TypeError):
        analyze_context(None)
