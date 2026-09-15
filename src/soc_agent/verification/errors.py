"""Verification errors do not imply remediation or retry authority."""


class VerificationError(Exception):
    """Root deterministic verification failure."""


class VerificationPlanningError(VerificationError):
    """Invalid draft, tool selection, or schema."""


class VerificationBindingError(VerificationError):
    """The incident, assessment, or completed response does not match."""


class VerificationStepStateError(VerificationError):
    """Invalid collection lifecycle transition."""


class VerificationStepNotFoundError(VerificationError):
    """Unknown verification step."""


class InvalidVerificationEvidenceError(VerificationError):
    """Evidence is not a valid collection from this verification plan."""


class NoVerificationEvidenceError(VerificationError):
    """No post-action evidence is available; do not call the LLM."""


class VerificationContextTooLargeError(VerificationError):
    """Context exceeds its bound; nothing was silently truncated."""


class InvalidVerificationDraftError(VerificationError):
    """Invalid structured verification assessment."""
