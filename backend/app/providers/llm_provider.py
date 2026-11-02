from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..schemas import TargetLLMResponse


class TargetLLMProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class MockLLMConfig:
    label: str = "offline_mock"


class TargetLLMProvider(ABC):
    @property
    @abstractmethod
    def is_mock(self) -> bool:
        """Whether this adapter returns synthetic output instead of a real LLM."""

    @abstractmethod
    async def generate(self, text: str, task: str) -> TargetLLMResponse:
        """Generate a provider response for already-approved content."""


class MockTargetLLMProvider(TargetLLMProvider):
    """Offline provider that never calls an external model."""

    @property
    def is_mock(self) -> bool:
        return True

    def __init__(self, config: MockLLMConfig | None = None) -> None:
        self.config = config or MockLLMConfig()

    async def generate(self, text: str, task: str) -> TargetLLMResponse:
        if not text.strip():
            raise TargetLLMProviderError("The supplied text is empty.")
        if not task.strip():
            raise TargetLLMProviderError("The supplied task is empty.")

        return TargetLLMResponse(
            provider=self.config.label,
            is_mock=True,
            is_synthetic=True,
            text=(
                "Synthetic mock response: no external LLM was called. "
                f"The mock received the task {task!r} and {len(text)} input characters."
            ),
        )


def get_target_llm_provider() -> TargetLLMProvider:
    return MockTargetLLMProvider()
