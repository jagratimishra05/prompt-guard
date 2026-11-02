from collections.abc import Awaitable, Callable

from ..schemas import (
    ContextualDetectorResult,
    Decision,
    DetectorResults,
    DetectorStatus,
    MLDetectorResult,
    RuleDetectorResult,
    ScanResponse,
)


SecurityAssessor = Callable[[str], Awaitable[ScanResponse] | ScanResponse]


class ScanServiceError(RuntimeError):
    pass


class TemporaryMockSecurityAssessmentError(ScanServiceError):
    pass


class ScanService:
    """Adapter between the API and the future detector/security integration."""

    def __init__(
        self,
        assessor: SecurityAssessor | None = None,
        *,
        is_temporary_mock: bool | None = None,
    ) -> None:
        self._assessor = assessor
        if is_temporary_mock is None:
            # Tests and callers must explicitly opt into non-mock status.
            is_temporary_mock = True
        self.is_temporary_mock = is_temporary_mock

    async def scan(self, text: str) -> ScanResponse:
        if self._assessor is None:
            return self._temporary_unavailable_assessment()

        try:
            result = self._assessor(text)
            if hasattr(result, "__await__"):
                result = await result
        except Exception as exc:
            raise ScanServiceError("Temporary security assessment failed.") from exc

        if isinstance(result, ScanResponse):
            return result
        if isinstance(result, dict):
            return ScanResponse.model_validate(result)
        raise ScanServiceError("Temporary security assessment returned an unsupported result.")

    @staticmethod
    def _temporary_unavailable_assessment() -> ScanResponse:
        failed_reason = "Temporary mock: detector integration is unavailable."
        return ScanResponse(
            decision=Decision.REVIEW,
            risk_score=50,
            reason="Temporary mock security assessment is unresolved; no LLM generation is permitted.",
            detectors=DetectorResults(
                rules=RuleDetectorResult(
                    status=DetectorStatus.FAILED,
                    prediction=None,
                    evidence=[],
                    reason=failed_reason,
                ),
                ml=MLDetectorResult(
                    status=DetectorStatus.FAILED,
                    prediction=None,
                    malicious_probability=None,
                    reason=failed_reason,
                ),
                contextual=ContextualDetectorResult(
                    status=DetectorStatus.SKIPPED,
                    prediction=None,
                    reason="Temporary mock: contextual analysis is unavailable.",
                ),
            ),
        )