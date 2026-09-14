"""Stable serialized values for the read-only investigation foundation."""

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    ASSESSING = "assessing"
    CLOSED = "closed"
