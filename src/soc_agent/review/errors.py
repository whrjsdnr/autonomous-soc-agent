"""Failures expose no partially updated incident state."""


class ReviewError(ValueError):
    """Invalid, unregistered or mismatched review artifact."""


class HumanAuthorizationDenied(ReviewError):
    """Trusted external confirmation absent or invalid."""


class StaleSnapshotError(ReviewError):
    """Review no longer addresses the authoritative current snapshot."""


class AuthorizationAlreadyApplied(ReviewError):
    """Authorization has already committed in this repository."""


class StateTransitionDenied(ReviewError):
    """Requested lifecycle change is outside the explicit versioned policy."""
