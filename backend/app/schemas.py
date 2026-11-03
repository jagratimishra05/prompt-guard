from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_INPUT_LENGTH = 10_000
MAX_TASK_LENGTH = 2_000


class DetectorStatus(str, Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class Prediction(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="allow")


def validate_non_empty_text(value: str, field_name: str, max_length: int) -> str:
    if not value.strip():
        raise ValueError(f"The {field_name} field must not be empty.")
    if len(value) > max_length:
        raise ValueError(f"The {field_name} field must not exceed {max_length} characters.")
    return value


class ScanRequest(ContractModel):
    text: str = Field(..., min_length=1)

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return validate_non_empty_text(value, "text", MAX_INPUT_LENGTH)


class ProtectedGenerateRequest(ScanRequest):
    task: str = Field(..., min_length=1, max_length=MAX_TASK_LENGTH)

    @field_validator("task")
    @classmethod
    def validate_task(cls, value: str) -> str:
        return validate_non_empty_text(value, "task", MAX_TASK_LENGTH)


class RuleDetectorResult(ContractModel):
    status: DetectorStatus
    prediction: Prediction | None = None
    evidence: list[str] = Field(default_factory=list)
    reason: str | None = None


class MLDetectorResult(ContractModel):
    status: DetectorStatus
    prediction: Prediction | None = None
    malicious_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    reason: str | None = None


class ContextualDetectorResult(ContractModel):
    status: DetectorStatus
    prediction: Prediction | None = None
    reason: str | None = None


class DetectorResults(ContractModel):
    rules: RuleDetectorResult
    ml: MLDetectorResult
    contextual: ContextualDetectorResult


class ScanResponse(ContractModel):
    decision: Decision
    risk_score: int = Field(..., ge=0, le=100)
    reason: str
    detectors: DetectorResults


class TargetLLMResponse(ContractModel):
    provider: str = "offline_mock"
    is_mock: bool = True
    is_synthetic: bool = True
    text: str


class ProtectedGenerateResponse(ScanResponse):
    generated_response: TargetLLMResponse | None = None


class ErrorDetail(ContractModel):
    code: str
    message: str


class ErrorResponse(ContractModel):
    error: ErrorDetail
