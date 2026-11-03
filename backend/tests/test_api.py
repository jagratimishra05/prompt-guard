from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.providers.llm_provider import TargetLLMProvider
from backend.app.schemas import (
    ContextualDetectorResult,
    Decision,
    DetectorResults,
    DetectorStatus,
    MLDetectorResult,
    Prediction,
    RuleDetectorResult,
    ScanResponse,
    TargetLLMResponse,
)
from backend.app.services.scan_service import ScanService


def assessment(decision: Decision) -> ScanResponse:
    risk_score = {
        Decision.ALLOW: 10,
        Decision.REVIEW: 50,
        Decision.BLOCK: 90,
    }[decision]
    prediction = Prediction.BENIGN if decision == Decision.ALLOW else Prediction.MALICIOUS
    return ScanResponse(
        decision=decision,
        risk_score=risk_score,
        reason=f"Temporary mock assessment: {decision.value}",
        detectors=DetectorResults(
            rules=RuleDetectorResult(
                status=DetectorStatus.COMPLETED,
                prediction=prediction,
                evidence=[] if decision == Decision.ALLOW else ["temporary_mock_indicator"],
                reason="Temporary mock detector result.",
            ),
            ml=MLDetectorResult(
                status=DetectorStatus.COMPLETED,
                prediction=prediction,
                malicious_probability=risk_score / 100,
                reason="Temporary mock detector result.",
            ),
            contextual=ContextualDetectorResult(
                status=DetectorStatus.SKIPPED,
                prediction=None,
                reason="Temporary mock: contextual analysis was not run.",
            ),
        ),
    )


class CountingProvider(TargetLLMProvider):
    def __init__(self) -> None:
        self.calls = 0

    @property
    def is_mock(self) -> bool:
        return True

    async def generate(self, text: str, task: str) -> TargetLLMResponse:
        self.calls += 1
        return TargetLLMResponse(
            provider="test_synthetic_mock",
            is_mock=True,
            is_synthetic=True,
            text=f"Synthetic response for {task}",
        )


class FailingProvider(TargetLLMProvider):
    @property
    def is_mock(self) -> bool:
        return False

    async def generate(self, text: str, task: str) -> TargetLLMResponse:
        raise RuntimeError("provider unavailable")


class CountingGeminiProvider(TargetLLMProvider):
    def __init__(self) -> None:
        self.calls = 0

    @property
    def is_mock(self) -> bool:
        return False

    async def generate(self, text: str, task: str) -> TargetLLMResponse:
        self.calls += 1
        return TargetLLMResponse(
            provider="google_gemini",
            is_mock=False,
            is_synthetic=False,
            text="Gemini response",
        )


def client_for(
    decision: Decision,
    provider: TargetLLMProvider | None = None,
) -> tuple[TestClient, TargetLLMProvider]:
    provider = provider or CountingProvider()
    service = ScanService(
        lambda text: assessment(decision),
        is_temporary_mock=False,
    )
    app = create_app(scan_service=service, target_provider=provider)
    return TestClient(app), provider  # type: ignore[return-value]


def test_health() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "PromptGuard"}


def test_scan_allow() -> None:
    client, _ = client_for(Decision.ALLOW)
    with client:
        response = client.post("/v1/scan", json={"text": "Normal external text"})
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["detectors"]["rules"]["status"] == "completed"


def test_scan_review_and_block() -> None:
    for decision in (Decision.REVIEW, Decision.BLOCK):
        client, _ = client_for(decision)
        with client:
            response = client.post("/v1/scan", json={"text": "Suspicious external text"})
        assert response.status_code == 200
        assert response.json()["decision"] == decision.value


def test_invalid_and_oversized_input() -> None:
    app = create_app()
    with TestClient(app) as client:
        missing = client.post("/v1/scan", json={})
        empty = client.post("/v1/scan", json={"text": "   "})
        oversized = client.post("/v1/scan", json={"text": "x" * 10_001})

    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "INVALID_INPUT"
    assert empty.status_code == 422
    assert oversized.status_code == 422


def test_allow_generation_calls_real_assessment_mock_provider() -> None:
    client, provider = client_for(Decision.ALLOW)
    with client:
        response = client.post(
            "/v1/protected-generate",
            json={"text": "External text", "task": "Summarize this"},
        )
    assert response.status_code == 200
    assert provider.calls == 1
    assert response.json()["generated_response"]["is_synthetic"] is True
    assert response.json()["generated_response"]["is_mock"] is True


def test_review_and_block_generation_do_not_call_provider() -> None:
    for decision in (Decision.REVIEW, Decision.BLOCK):
        client, provider = client_for(decision)
        with client:
            response = client.post(
                "/v1/protected-generate",
                json={"text": "External text", "task": "Summarize this"},
            )
        assert response.status_code == 200
        assert response.json()["decision"] == decision.value
        assert response.json()["generated_response"] is None
        assert provider.calls == 0


def test_failed_assessment_does_not_call_provider() -> None:
    provider = CountingProvider()
    service = ScanService(
        lambda text: (_ for _ in ()).throw(RuntimeError("detector failed")),
        is_temporary_mock=False,
    )

    app = create_app(scan_service=service, target_provider=provider)
    with TestClient(app) as client:
        response = client.post(
            "/v1/protected-generate",
            json={"text": "External text", "task": "Summarize this"},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "SCAN_FAILED"
    assert provider.calls == 0


def test_target_provider_failure_returns_structured_error() -> None:
    app = create_app(
        scan_service=ScanService(
            lambda text: assessment(Decision.ALLOW),
            is_temporary_mock=False,
        ),
        target_provider=FailingProvider(),
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/protected-generate",
            json={"text": "External text", "task": "Summarize this"},
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "TARGET_PROVIDER_FAILED"


def test_default_security_mock_never_enables_generation() -> None:
    provider = CountingProvider()
    app = create_app(
        scan_service=ScanService(is_temporary_mock=True),
        target_provider=provider,
    )
    with TestClient(app) as client:
        scan = client.post("/v1/scan", json={"text": "External text"})
        protected = client.post(
            "/v1/protected-generate",
            json={"text": "External text", "task": "Summarize this"},
        )

    assert scan.status_code == 200
    assert scan.json()["decision"] == "REVIEW"
    assert protected.status_code == 200
    assert protected.json()["generated_response"] is None
    assert provider.calls == 0


def test_mock_security_allow_never_calls_provider() -> None:
    provider = CountingProvider()
    service = ScanService(
        lambda text: assessment(Decision.ALLOW),
        is_temporary_mock=True,
    )
    app = create_app(scan_service=service, target_provider=provider)

    with TestClient(app) as client:
        response = client.post(
            "/v1/protected-generate",
            json={"text": "External text", "task": "Summarize this"},
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "MOCK_SECURITY_ASSESSMENT"
    assert provider.calls == 0


def test_gemini_provider_is_not_called_for_review_or_block() -> None:
    for decision in (Decision.REVIEW, Decision.BLOCK):
        provider = CountingGeminiProvider()
        service = ScanService(
            lambda text, decision=decision: assessment(decision),
            is_temporary_mock=False,
        )
        app = create_app(scan_service=service, target_provider=provider)

        with TestClient(app) as client:
            response = client.post(
                "/v1/protected-generate",
                json={"text": "Suspicious text", "task": "Summarize"},
            )

        assert response.status_code == 200
        assert response.json()["generated_response"] is None
        assert provider.calls == 0
