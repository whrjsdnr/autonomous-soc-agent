"""Deterministic selection failures, distinct from LLM failures."""


class SecurityAISelectionError(Exception):
    """Selection cannot produce a complete valid plan."""


class NoSecurityAIAvailableError(SecurityAISelectionError):
    """No registered models; do not call the LLM."""


class UnknownSelectedModelError(SecurityAISelectionError):
    """Selected model is outside the request's registry snapshot."""


class InvalidSelectedModelInputError(SecurityAISelectionError):
    """Input fails the selected schema or JSON round trip."""


class InvalidAISignalContextError(SecurityAISelectionError):
    """Signal context fails incident, reference, or uniqueness validation."""


class SelectionContextTooLargeError(SecurityAISelectionError):
    """Projected request exceeds the deterministic character budget."""
