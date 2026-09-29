"""Fail-closed durable execution errors."""

from soc_agent.execution.errors import ExecutionError


class DurableExecutionError(ExecutionError):
    pass


class ClaimConflict(DurableExecutionError):
    pass


class ExecutionReplay(DurableExecutionError):
    pass


class ExecutionOutcomeUnknown(DurableExecutionError):
    """Read durable state on a fresh connection; never retry the external operation."""
