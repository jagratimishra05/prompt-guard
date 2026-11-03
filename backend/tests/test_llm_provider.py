import asyncio
import os
import logging

import pytest

from backend.app.providers.llm_provider import (
    GeminiLLMConfig,
    GeminiTargetLLMProvider,
    MockTargetLLMProvider,
    TargetLLMProviderError,
    get_target_llm_provider,
    load_promptguard_env,
)


class FakeModels:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.error, list):
            error = self.error.pop(0) if self.error else None
        else:
            error = self.error
        if isinstance(self.response, list):
            response = self.response.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        return_response = self.response
        if error:
            raise error
        return return_response


class FakeClient:
    def __init__(self, response=None, error=None):
        self.models = FakeModels(response=response, error=error)


class FakeResponse:
    def __init__(self, text):
        self.text = text


def run(coro):
    return asyncio.run(coro)


def valid_config(api_key="test-api-key"):
    return GeminiLLMConfig(api_key=api_key, model="gemini-test", timeout_seconds=1)


def test_mock_provider_remains_available():
    provider = MockTargetLLMProvider()
    result = run(provider.generate("Approved text", "Summarize it"))

    assert provider.is_mock is True
    assert result.is_mock is True
    assert result.is_synthetic is True
    assert result.provider == "offline_mock"


def test_gemini_successful_response(monkeypatch):
    client = FakeClient(response=FakeResponse("Real Gemini response"))
    provider = GeminiTargetLLMProvider(valid_config(), client=client)

    result = run(provider.generate("Approved text", "Summarize it"))

    assert provider.is_mock is False
    assert result.is_mock is False
    assert result.is_synthetic is False
    assert result.provider == "google_gemini"
    assert result.text == "Real Gemini response"
    assert client.models.calls[0]["model"] == "gemini-test"
    assert "Approved text" in client.models.calls[0]["contents"]


@pytest.mark.parametrize("api_key", ["", "your-gemini-api-key-here"])
def test_gemini_missing_or_placeholder_api_key(api_key):
    provider = GeminiTargetLLMProvider(valid_config(api_key))

    with pytest.raises(TargetLLMProviderError, match="GEMINI_API_KEY"):
        run(provider.generate("Approved text", "Summarize it"))


def test_gemini_empty_model_is_invalid():
    provider = GeminiTargetLLMProvider(
        GeminiLLMConfig(api_key="test-api-key", model="  ")
    )

    with pytest.raises(TargetLLMProviderError, match="GEMINI_MODEL"):
        run(provider.generate("Approved text", "Summarize it"))


def test_gemini_sdk_error_is_wrapped():
    provider = GeminiTargetLLMProvider(
        valid_config(),
        client=FakeClient(error=RuntimeError("API failure")),
    )

    with pytest.raises(TargetLLMProviderError, match="Gemini provider request failed"):
        run(provider.generate("Approved text", "Summarize it"))


def test_gemini_503_retries_then_succeeds(monkeypatch):
    class ServerError(RuntimeError):
        code = 503

    fake_models = FakeModels(
        response=[ServerError("capacity unavailable"), FakeResponse("Recovered response")],
        error=None,
    )
    client = FakeClient(response=fake_models.response)
    client.models = fake_models
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    provider = GeminiTargetLLMProvider(valid_config(), client=client)

    result = run(provider.generate("Approved text", "Summarize it"))

    assert result.text == "Recovered response"
    assert len(fake_models.calls) == 2
    assert sleeps == [1.0]


def test_gemini_exhausted_503_preserves_status(monkeypatch):
    class ServerError(RuntimeError):
        code = 503

    client = FakeClient(
        response=[ServerError("capacity unavailable"), ServerError("capacity unavailable")],
    )
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    provider = GeminiTargetLLMProvider(valid_config(), client=client)

    with pytest.raises(TargetLLMProviderError) as exc_info:
        run(provider.generate("Approved text", "Summarize it"))

    assert exc_info.value.status_code == 503
    assert sleeps == [1.0]


def test_gemini_retry_after_is_respected(monkeypatch):
    class RateLimitError(RuntimeError):
        code = 429
        headers = {"Retry-After": "2.5"}

    client = FakeClient(
        response=[RateLimitError("rate limited"), FakeResponse("Recovered response")],
    )
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    provider = GeminiTargetLLMProvider(valid_config(), client=client)

    result = run(provider.generate("Approved text", "Summarize it"))

    assert result.text == "Recovered response"
    assert sleeps == [2.5]


def test_gemini_sdk_error_logging_is_secret_safe(caplog):
    class StatusError(RuntimeError):
        code = 404

    provider = GeminiTargetLLMProvider(
        GeminiLLMConfig(api_key="secret-api-key", model="gemini-test"),
        client=FakeClient(error=StatusError(
            "secret-api-key Approved-text-secret Task-secret"
        )),
    )

    with caplog.at_level(logging.ERROR, logger="backend.app.providers.llm_provider"):
        with pytest.raises(TargetLLMProviderError):
            run(provider.generate("Approved-text-secret", "Task-secret"))

    record = caplog.records[-1].getMessage()
    assert "StatusError" in record
    assert "status=404" in record
    assert "secret-api-key" not in record
    assert "Approved-text-secret" not in record
    assert "Task-secret" not in record


@pytest.mark.parametrize(
    "response",
    [
        None,
        FakeResponse(""),
        object(),
        FakeResponse("   "),
    ],
)
def test_gemini_empty_or_unexpected_response_is_rejected(response):
    provider = GeminiTargetLLMProvider(valid_config(), client=FakeClient(response=response))

    with pytest.raises(TargetLLMProviderError, match="empty or invalid response"):
        run(provider.generate("Approved text", "Summarize it"))


def test_gemini_timeout_is_wrapped(monkeypatch):
    provider = GeminiTargetLLMProvider(
        GeminiLLMConfig(api_key="test-api-key", model="gemini-test", timeout_seconds=0),
        client=FakeClient(response=FakeResponse("too slow")),
    )

    with pytest.raises(TargetLLMProviderError, match="timed out"):
        run(provider.generate("Approved text", "Summarize it"))


def test_gemini_timeout_logging_is_secret_safe(caplog):
    provider = GeminiTargetLLMProvider(
        GeminiLLMConfig(api_key="secret-api-key", model="gemini-test", timeout_seconds=0),
        client=FakeClient(error=asyncio.TimeoutError(
            "secret-api-key Approved-text-secret Task-secret"
        )),
    )

    with caplog.at_level(logging.ERROR, logger="backend.app.providers.llm_provider"):
        with pytest.raises(TargetLLMProviderError, match="timed out"):
            run(provider.generate("Approved-text-secret", "Task-secret"))

    record = caplog.records[-1].getMessage()
    assert "TimeoutError" in record
    assert "status=timeout" in record
    assert "secret-api-key" not in record
    assert "Approved-text-secret" not in record
    assert "Task-secret" not in record


def test_environment_factory_selects_mock(monkeypatch):
    monkeypatch.setenv("TARGET_LLM_PROVIDER", "mock")
    assert isinstance(get_target_llm_provider(), MockTargetLLMProvider)


def test_environment_factory_does_not_fallback_from_gemini(monkeypatch):
    monkeypatch.setenv("TARGET_LLM_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "real-provider-test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")

    provider = get_target_llm_provider()

    assert isinstance(provider, GeminiTargetLLMProvider)
    assert provider.is_mock is False


def test_root_env_file_loads_gemini_configuration(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TARGET_LLM_PROVIDER=gemini\n"
        "GEMINI_API_KEY=test-dotenv-key\n"
        "GEMINI_MODEL=gemini-dotenv-test\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("TARGET_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    try:
        load_promptguard_env(env_file)

        provider = get_target_llm_provider()

        assert isinstance(provider, GeminiTargetLLMProvider)
        assert provider.config.api_key == "test-dotenv-key"
        assert provider.config.model == "gemini-dotenv-test"
    finally:
        os.environ.pop("TARGET_LLM_PROVIDER", None)
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("GEMINI_MODEL", None)
