"""Interpretation states, never incident severity or execution permissions."""

from enum import StrEnum


class AgreementState(StrEnum):
    CONSISTENT = "consistent"
    PARTIAL = "partial"
    CONFLICTING = "conflicting"
    INSUFFICIENT = "insufficient"


class ConfidenceState(StrEnum):
    UNKNOWN = "unknown"


class CoverageState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    NONE = "none"
