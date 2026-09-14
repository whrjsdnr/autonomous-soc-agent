"""Governance failures; existing ToolError and ApprovalError remain distinct."""


class ExecutionError(Exception):
    """Root of governed execution failures."""


class ExecutionDeniedError(ExecutionError):
    """Policy forbids the action."""


class ApprovalRequiredError(ExecutionError):
    """Exact human approval is absent or pending."""


class ApprovalRejectedError(ExecutionError):
    """The human rejected the action."""


class ApprovalBindingError(ExecutionError):
    """Approval does not match the complete action and current tool metadata."""


class ActionAlreadyAttemptedError(ExecutionError):
    """This executor has already handed the action to the tool boundary."""
