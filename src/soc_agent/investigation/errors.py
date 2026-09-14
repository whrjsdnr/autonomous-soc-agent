"""Investigation consistency and conversion errors."""


class InvestigationError(Exception):
    """Root of investigation-specific errors."""


class InvestigationPlanMismatchError(InvestigationError):
    """Plan and incident state do not belong together."""


class InvestigationStepNotFoundError(InvestigationError):
    """Step ID is absent from the plan."""


class InvestigationStepStateError(InvestigationError):
    """Step cannot be executed or transitioned from its current state."""


class EvidenceConversionError(InvestigationError):
    """Successful tool output could not be faithfully recorded as evidence."""
