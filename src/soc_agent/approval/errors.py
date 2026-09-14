"""Approval boundary errors with no implied retry behavior."""


class ApprovalError(Exception):
    """Root of manager failures."""


class ApprovalNotFoundError(ApprovalError):
    """No request exists for the supplied ID."""


class ApprovalAlreadyDecidedError(ApprovalError):
    """A terminal decision cannot be replaced."""


class ApprovalValidationError(ApprovalError):
    """Request or human decision input is invalid."""
