"""Public exports loaded on demand; importing a Controller must not load AI models."""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.security_ai.base import SecurityAI as SecurityAI
    from soc_agent.security_ai.base import SecurityAIHandler as SecurityAIHandler
    from soc_agent.security_ai.context import build_ai_signal_context as build_ai_signal_context
    from soc_agent.security_ai.enums import SecurityAIInputType as SecurityAIInputType
    from soc_agent.security_ai.enums import SecurityAITaskType as SecurityAITaskType
    from soc_agent.security_ai.errors import SecurityAIError as SecurityAIError
    from soc_agent.security_ai.errors import SecurityAIInferenceError as SecurityAIInferenceError
    from soc_agent.security_ai.errors import (
        SecurityAIInputValidationError as SecurityAIInputValidationError,
    )
    from soc_agent.security_ai.errors import SecurityAILookupError as SecurityAILookupError
    from soc_agent.security_ai.errors import (
        SecurityAIMockExhaustedError as SecurityAIMockExhaustedError,
    )
    from soc_agent.security_ai.errors import (
        SecurityAIOutputValidationError as SecurityAIOutputValidationError,
    )
    from soc_agent.security_ai.errors import (
        SecurityAIRegistrationError as SecurityAIRegistrationError,
    )
    from soc_agent.security_ai.investigation_errors import (
        SecurityAIInvestigationError as SecurityAIInvestigationError,
    )
    from soc_agent.security_ai.investigation_models import (
        SecurityAIInvestigationResult as SecurityAIInvestigationResult,
    )
    from soc_agent.security_ai.investigation_models import (
        SecurityAIInvestigationStep as SecurityAIInvestigationStep,
    )
    from soc_agent.security_ai.investigation_models import (
        SecurityAIInvestigationStepStatus as SecurityAIInvestigationStepStatus,
    )
    from soc_agent.security_ai.investigator import SecurityAIInvestigator as SecurityAIInvestigator
    from soc_agent.security_ai.mock import MockSecurityAI as MockSecurityAI
    from soc_agent.security_ai.models import SecurityAIModelMetadata as SecurityAIModelMetadata
    from soc_agent.security_ai.models import SecurityAIPrediction as SecurityAIPrediction
    from soc_agent.security_ai.models import SecurityAIRequest as SecurityAIRequest
    from soc_agent.security_ai.models import SecurityAIResult as SecurityAIResult
    from soc_agent.security_ai.registry import SecurityAIRegistry as SecurityAIRegistry
    from soc_agent.security_ai.selection_errors import (
        InvalidAISignalContextError as InvalidAISignalContextError,
    )
    from soc_agent.security_ai.selection_errors import (
        InvalidSelectedModelInputError as InvalidSelectedModelInputError,
    )
    from soc_agent.security_ai.selection_errors import (
        NoSecurityAIAvailableError as NoSecurityAIAvailableError,
    )
    from soc_agent.security_ai.selection_errors import (
        SecurityAISelectionError as SecurityAISelectionError,
    )
    from soc_agent.security_ai.selection_errors import (
        SelectionContextTooLargeError as SelectionContextTooLargeError,
    )
    from soc_agent.security_ai.selection_errors import (
        UnknownSelectedModelError as UnknownSelectedModelError,
    )
    from soc_agent.security_ai.selection_models import (
        SecurityAISelectionDecision as SecurityAISelectionDecision,
    )
    from soc_agent.security_ai.selection_models import (
        SecurityAISelectionDraft as SecurityAISelectionDraft,
    )
    from soc_agent.security_ai.selection_models import (
        SecurityAISelectionPlan as SecurityAISelectionPlan,
    )
    from soc_agent.security_ai.selection_models import (
        SecurityAISelectionStep as SecurityAISelectionStep,
    )
    from soc_agent.security_ai.selection_models import (
        SecurityAISelectionStepDraft as SecurityAISelectionStepDraft,
    )
    from soc_agent.security_ai.selector import SecurityAISelector as SecurityAISelector
    from soc_agent.security_ai.signals import AISignal as AISignal
    from soc_agent.security_ai.signals import create_ai_signal as create_ai_signal

_EXPORTS = {
    "SecurityAIInvestigationError": "soc_agent.security_ai.investigation_errors",
    "SecurityAIInvestigationResult": "soc_agent.security_ai.investigation_models",
    "SecurityAIInvestigationStep": "soc_agent.security_ai.investigation_models",
    "SecurityAIInvestigationStepStatus": "soc_agent.security_ai.investigation_models",
    "SecurityAIInvestigator": "soc_agent.security_ai.investigator",
    "SecurityAISelectionDecision": "soc_agent.security_ai.selection_models",
    "SecurityAISelectionDraft": "soc_agent.security_ai.selection_models",
    "SecurityAISelectionPlan": "soc_agent.security_ai.selection_models",
    "SecurityAISelectionStep": "soc_agent.security_ai.selection_models",
    "SecurityAISelectionStepDraft": "soc_agent.security_ai.selection_models",
    "SecurityAISelectionError": "soc_agent.security_ai.selection_errors",
    "NoSecurityAIAvailableError": "soc_agent.security_ai.selection_errors",
    "UnknownSelectedModelError": "soc_agent.security_ai.selection_errors",
    "InvalidSelectedModelInputError": "soc_agent.security_ai.selection_errors",
    "InvalidAISignalContextError": "soc_agent.security_ai.selection_errors",
    "SelectionContextTooLargeError": "soc_agent.security_ai.selection_errors",
    "SecurityAISelector": "soc_agent.security_ai.selector",
    "AISignal": "soc_agent.security_ai.signals",
    "build_ai_signal_context": "soc_agent.security_ai.context",
    "create_ai_signal": "soc_agent.security_ai.signals",
    "MockSecurityAI": "soc_agent.security_ai.mock",
    "SecurityAI": "soc_agent.security_ai.base",
    "SecurityAIError": "soc_agent.security_ai.errors",
    "SecurityAIHandler": "soc_agent.security_ai.base",
    "SecurityAIInferenceError": "soc_agent.security_ai.errors",
    "SecurityAIInputType": "soc_agent.security_ai.enums",
    "SecurityAIInputValidationError": "soc_agent.security_ai.errors",
    "SecurityAILookupError": "soc_agent.security_ai.errors",
    "SecurityAIMockExhaustedError": "soc_agent.security_ai.errors",
    "SecurityAIModelMetadata": "soc_agent.security_ai.models",
    "SecurityAIOutputValidationError": "soc_agent.security_ai.errors",
    "SecurityAIPrediction": "soc_agent.security_ai.models",
    "SecurityAIRegistrationError": "soc_agent.security_ai.errors",
    "SecurityAIRegistry": "soc_agent.security_ai.registry",
    "SecurityAIRequest": "soc_agent.security_ai.models",
    "SecurityAIResult": "soc_agent.security_ai.models",
    "SecurityAITaskType": "soc_agent.security_ai.enums",
}
__all__ = list(_EXPORTS)


def __getattr__(name: str):
    try:
        module = _EXPORTS[name]
    except KeyError:
        raise AttributeError(name) from None
    return getattr(import_module(module), name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))
