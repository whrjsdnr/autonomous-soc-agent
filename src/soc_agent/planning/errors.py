"""Planning failures, separate from LLM transport/response failures."""


class PlanningError(Exception):
    """Root of deterministic planning failures."""


class UnknownPlannedToolError(PlanningError):
    """Draft selected a tool outside the planning snapshot."""


class InvalidPlannedToolInputError(PlanningError):
    """Draft input cannot be validated or represented for execution."""


class InvalidPlanError(PlanningError):
    """Draft cannot be normalized into a plan."""
