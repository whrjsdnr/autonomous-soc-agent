"""Validated security model predictions, independent of tools and LLM reasoning."""

from soc_agent.security_ai.base import SecurityAI, SecurityAIHandler
from soc_agent.security_ai.context import build_ai_signal_context
from soc_agent.security_ai.enums import SecurityAIInputType, SecurityAITaskType
from soc_agent.security_ai.errors import (
    SecurityAIError,
    SecurityAIInferenceError,
    SecurityAIInputValidationError,
    SecurityAILookupError,
    SecurityAIMockExhaustedError,
    SecurityAIOutputValidationError,
    SecurityAIRegistrationError,
)
from soc_agent.security_ai.mock import MockSecurityAI
from soc_agent.security_ai.models import (
    SecurityAIModelMetadata,
    SecurityAIPrediction,
    SecurityAIRequest,
    SecurityAIResult,
)
from soc_agent.security_ai.registry import SecurityAIRegistry
from soc_agent.security_ai.signals import AISignal, create_ai_signal

__all__ = [
    "AISignal",
    "build_ai_signal_context",
    "create_ai_signal",
    "MockSecurityAI",
    "SecurityAI",
    "SecurityAIError",
    "SecurityAIHandler",
    "SecurityAIInferenceError",
    "SecurityAIInputType",
    "SecurityAIInputValidationError",
    "SecurityAILookupError",
    "SecurityAIMockExhaustedError",
    "SecurityAIModelMetadata",
    "SecurityAIOutputValidationError",
    "SecurityAIPrediction",
    "SecurityAIRegistrationError",
    "SecurityAIRegistry",
    "SecurityAIRequest",
    "SecurityAIResult",
    "SecurityAITaskType",
]
