"""Stable exceptions for callers, independent of provider SDKs."""


class LLMError(Exception):
    """Base for LLM execution failures; does not imply retryability."""


class LLMTimeoutError(LLMError):
    """An LLM operation exceeded its deadline."""


class LLMResponseValidationError(LLMError):
    """The response failed the caller's structured output schema."""


class LLMMockExhaustedError(LLMError):
    """No configured response remains; the test fixture needs attention."""
