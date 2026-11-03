from collections.abc import Awaitable, Callable
from typing import Any

from ..detectors.ml_detector import detect_with_ml
from ..detectors.rule_detector import detect_prompt_injection
from ..security.contextual_detector import analyze_context
from ..security.risk_engine import assess_risk
from ..security.router import route_detectors

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
DetectorCallable = Callable[[str], dict[str, Any] | Awaitable[dict[str, Any]]]
ContextualCallable = Callable[..., dict[str, Any] | Awaitable[dict[str, Any]]]
RiskCallable = Callable[..., dict[str, Any] | Awaitable[dict[str, Any]]]


class ScanServiceError(RuntimeError):
    pass


class TemporaryMockSecurityAssessmentError(ScanServiceError):
    pass


class ScanService:
    """Adapter and fail-safe orchestrator for the real security pipeline."""

    def __init__(
        self,
        assessor: SecurityAssessor | None = None,
        *,
        is_temporary_mock: bool | None = None,
        rule_detector: DetectorCallable | None = None,
        ml_detector: DetectorCallable | None = None,
        contextual_detector: ContextualCallable | None = None,
        detector_router: Callable[..., dict[str, Any]] | None = None,
        risk_assessor: RiskCallable | None = None,
        contextual_enabled: bool = False,
    ) -> None:
        self._assessor = assessor
        if is_temporary_mock is None:
            is_temporary_mock = assessor is not None
        self.is_temporary_mock = is_temporary_mock
        self._rule_detector = rule_detector or detect_prompt_injection
        self._ml_detector = ml_detector or detect_with_ml
        self._contextual_detector = contextual_detector or analyze_context
        self._detector_router = detector_router or route_detectors
        self._risk_assessor = risk_assessor or assess_risk
        self.contextual_enabled = contextual_enabled

    async def scan(self, text: str) -> ScanResponse:
        if self._assessor is None:
            if self.is_temporary_mock:
                return self._temporary_unavailable_assessment()
            return await self._scan_real_pipeline(text)

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

    async def _call(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        result = function(*args, **kwargs)
        if hasattr(result, "__await__"):
            result = await result
        return result

    async def _scan_real_pipeline(self, text: str) -> ScanResponse:
        rules = await self._run_rules(text)

        try:
            initial_route = self._detector_router(text)
            self._validate_router_result(initial_route, require_rules=True)
            routed = self._detector_router(
                text,
                rules,
                contextual_enabled=self.contextual_enabled,
            )
            self._validate_router_result(routed)
        except Exception:
            ml = self._failed_result("ML detection could not be routed.")
            contextual = self._failed_contextual(
                "Contextual routing failed and the result is unresolved."
            )
            return await self._assess_or_fail_closed(text, rules, ml, contextual)

        if routed["detectors"]["ml"]:
            ml = await self._run_ml(text)
        else:
            ml = self._failed_result("ML detection was not selected by routing.")

        if routed["detectors"]["contextual"]:
            contextual = await self._run_contextual(text, enabled=True)
        else:
            contextual = await self._run_contextual(text, enabled=False)

        return await self._assess_or_fail_closed(text, rules, ml, contextual)

    async def _run_rules(self, text: str) -> dict[str, Any]:
        try:
            raw = await self._call(self._rule_detector, text)
            return self._normalize_rules(raw)
        except Exception:
            return self._failed_result(
                "Rules detector failed; the result is unresolved.",
            )

    async def _run_ml(self, text: str) -> dict[str, Any]:
        try:
            raw = await self._call(self._ml_detector, text)
            return self._normalize_ml(raw)
        except Exception:
            return self._failed_result(
                "ML detector failed; the result is unresolved.",
            )

    async def _run_contextual(self, text: str, *, enabled: bool) -> dict[str, Any]:
        try:
            raw = await self._call(self._contextual_detector, text, enabled=enabled)
            return self._normalize_contextual(raw, enabled=enabled)
        except Exception:
            if enabled:
                return self._failed_contextual(
                    "Contextual detector failed; the result is unresolved.",
                )
            return self._skipped_contextual(
                "Contextual analysis was skipped.",
            )

    @staticmethod
    def _validate_router_result(result: Any, *, require_rules: bool = False) -> None:
        if not isinstance(result, dict):
            raise ValueError("Router returned a non-object result.")
        detectors = result.get("detectors")
        if not isinstance(detectors, dict):
            raise ValueError("Router result is missing detectors.")
        for name in ("rule", "ml", "contextual"):
            if name not in detectors or not isinstance(detectors[name], bool):
                raise ValueError(f"Router result has invalid '{name}' selection.")
        if require_rules and detectors["rule"] is not True:
            raise ValueError("Router did not start with rule detection.")
        if not isinstance(result.get("next_step"), str):
            raise ValueError("Router result is missing next_step.")
        if require_rules and result["next_step"] != "run_rule":
            raise ValueError("Router initial step must be run_rule.")

    @staticmethod
    def _normalize_rules(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError("Rules detector returned a non-object result.")
        required = ("is_suspicious", "risk_score", "risk_level", "matched_rules", "message")
        if any(name not in raw for name in required):
            raise ValueError("Rules detector result is missing required fields.")
        suspicious = raw["is_suspicious"]
        score = raw["risk_score"]
        level = raw["risk_level"]
        evidence = raw["matched_rules"]
        message = raw["message"]
        if (
            isinstance(suspicious, bool) is False
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or level not in {"low", "medium", "high"}
            or not isinstance(evidence, list)
            or not all(isinstance(item, str) for item in evidence)
            or not isinstance(message, str)
        ):
            raise ValueError("Rules detector returned malformed fields.")
        return {
            "status": "completed",
            "prediction": "malicious" if suspicious else "benign",
            "evidence": evidence,
            "reason": message,
        }

    @staticmethod
    def _normalize_ml(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError("ML detector returned a non-object result.")
        if not all(name in raw for name in ("prediction", "probability", "message")):
            raise ValueError("ML detector result is missing required fields.")
        prediction = raw["prediction"]
        probability = raw["probability"]
        message = raw["message"]
        if prediction not in {"malicious", "benign"}:
            raise ValueError("ML detector returned an invalid prediction.")
        if (
            isinstance(probability, bool)
            or not isinstance(probability, (int, float))
            or not 0 <= probability <= 1
            or not isinstance(message, str)
        ):
            raise ValueError("ML detector returned malformed fields.")
        return {
            "status": "completed",
            "prediction": prediction,
            "malicious_probability": float(probability),
            "reason": message,
        }

    @staticmethod
    def _normalize_contextual(raw: Any, *, enabled: bool) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValueError("Contextual detector returned a non-object result.")
        status = raw.get("status")
        prediction = raw.get("prediction")
        reason = raw.get("reason")
        if status == "skipped":
            if enabled or prediction is not None or not isinstance(reason, str):
                raise ValueError("Contextual detector returned an inconsistent skipped result.")
            return {
                "status": "skipped",
                "prediction": None,
                "reason": reason,
            }
        if status not in {"completed", "failed"}:
            raise ValueError("Contextual detector returned an invalid status.")
        if status == "completed":
            if prediction not in {"malicious", "benign"} or not isinstance(reason, str):
                raise ValueError("Contextual detector returned malformed completed fields.")
        elif prediction is not None:
            raise ValueError("Failed contextual detector must not contain a prediction.")
        normalized = {
            "status": status,
            "prediction": prediction,
            "reason": reason if isinstance(reason, str) else None,
        }
        provider = raw.get("provider")
        if provider is not None:
            if not isinstance(provider, str):
                raise ValueError("Contextual provider must be a string.")
            normalized["provider"] = provider
        return normalized

    @staticmethod
    def _failed_result(reason: str) -> dict[str, Any]:
        return {
            "status": "failed",
            "prediction": None,
            "evidence": [],
            "reason": reason,
        }

    @staticmethod
    def _failed_contextual(reason: str) -> dict[str, Any]:
        return {
            "status": "failed",
            "prediction": None,
            "reason": reason,
        }

    @staticmethod
    def _skipped_contextual(reason: str) -> dict[str, Any]:
        return {
            "status": "skipped",
            "prediction": None,
            "reason": reason,
        }

    async def _assess_or_fail_closed(
        self,
        text: str,
        rules: dict[str, Any],
        ml: dict[str, Any],
        contextual: dict[str, Any],
    ) -> ScanResponse:
        try:
            raw = await self._call(self._risk_assessor, rules, ml, contextual)
            return self._normalize_assessment(rules, ml, contextual, raw)
        except Exception:
            return self._fail_closed_assessment(rules, ml, contextual)

    def _normalize_assessment(
        self,
        rules: dict[str, Any],
        ml: dict[str, Any],
        contextual: dict[str, Any],
        raw: Any,
    ) -> ScanResponse:
        if (
            not isinstance(raw, dict)
            or raw.get("decision") not in {"ALLOW", "REVIEW", "BLOCK"}
            or not isinstance(raw.get("reason"), str)
            or not raw["reason"].strip()
            or isinstance(raw.get("risk_score"), bool)
            or not isinstance(raw.get("risk_score"), int)
            or not 0 <= raw["risk_score"] <= 100
        ):
            return self._fail_closed_assessment(rules, ml, contextual)

        if raw["decision"] == "ALLOW":
            if (
                rules.get("status") != "completed"
                or rules.get("prediction") not in {"benign", "malicious"}
                or ml.get("status") != "completed"
                or ml.get("prediction") not in {"benign", "malicious"}
                or contextual.get("status") == "failed"
                or (
                    self.contextual_enabled
                    and contextual.get("status") != "completed"
                )
                or raw["risk_score"] >= 30
            ):
                return self._fail_closed_assessment(rules, ml, contextual)

        return ScanResponse(
            decision=raw["decision"],
            risk_score=raw["risk_score"],
            reason=raw["reason"],
            detectors=DetectorResults(
                rules=RuleDetectorResult.model_validate(rules),
                ml=MLDetectorResult.model_validate({
                    key: value for key, value in ml.items()
                    if key in {"status", "prediction", "malicious_probability", "reason"}
                }),
                contextual=ContextualDetectorResult.model_validate(contextual),
            ),
        )

    def _fail_closed_assessment(
        self,
        rules: dict[str, Any],
        ml: dict[str, Any],
        contextual: dict[str, Any],
    ) -> ScanResponse:
        malicious = any(
            result.get("status") == "completed"
            and result.get("prediction") == "malicious"
            for result in (rules, ml, contextual)
        )
        decision = Decision.BLOCK if malicious else Decision.REVIEW
        return ScanResponse(
            decision=decision,
            risk_score=90 if decision == Decision.BLOCK else 50,
            reason="Real security assessment failed; fail-safe review is required.",
            detectors=DetectorResults(
                rules=RuleDetectorResult.model_validate(rules),
                ml=MLDetectorResult.model_validate({
                    key: value for key, value in ml.items()
                    if key in {"status", "prediction", "malicious_probability", "reason"}
                }),
                contextual=ContextualDetectorResult.model_validate(contextual),
            ),
        )

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