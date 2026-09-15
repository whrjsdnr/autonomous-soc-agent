"""Execution input errors and safe preflight failures."""


class SecurityAIInvestigationError(Exception):
    """Invalid execution envelope; inference has not started."""


class SecurityAIPreflightError(SecurityAIInvestigationError):
    """A selected step cannot run against current application bindings."""
