"""Replanning validation failures, distinct from provider errors."""


class AdaptivePlanningError(Exception):
    """Context or next decision cannot be used for bounded investigation."""


class InvalidInvestigationContextError(AdaptivePlanningError):
    """Context is empty, inconsistent, or references another incident."""


class RepeatedInvestigationError(AdaptivePlanningError):
    """Proposed capability/input already appears in supplied history."""


class AdaptiveContextTooLargeError(AdaptivePlanningError):
    """Projected user context exceeds 64000 characters."""
