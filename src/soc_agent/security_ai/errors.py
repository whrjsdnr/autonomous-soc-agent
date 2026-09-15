"""Boundary failures, with no implied retry or fallback behavior."""


class SecurityAIError(Exception):
    """Root of Security AI failures."""


class SecurityAIRegistrationError(SecurityAIError):
    """Invalid wrapper configuration or duplicate model name."""


class SecurityAILookupError(SecurityAIError):
    """Model is not in the registry allowlist."""


class SecurityAIInputValidationError(SecurityAIError):
    """Request or model input failed validation before inference."""


class SecurityAIInferenceError(SecurityAIError):
    """Inference handler failed."""


class SecurityAIOutputValidationError(SecurityAIError):
    """Handler output does not satisfy the prediction contract."""


class SecurityAIMockExhaustedError(SecurityAIInferenceError):
    """No configured mock response remains."""
