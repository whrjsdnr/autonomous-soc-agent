"""Failures classified for future retry, replan, or escalation decisions."""


class ToolError(Exception):
    """Root of tool boundary failures; no retryability is implied."""


class ToolRegistrationError(ToolError):
    """Invalid configuration or duplicate registration."""


class ToolNotFoundError(ToolError):
    """The requested name is not in the execution allowlist."""


class ToolInputValidationError(ToolError):
    """Input failed validation before execution."""


class ToolOutputValidationError(ToolError):
    """Implementation output failed validation after execution."""


class ToolExecutionError(ToolError):
    """The implementation failed during execution."""


class ToolMockExhaustedError(ToolExecutionError):
    """No configured mock response remains."""
