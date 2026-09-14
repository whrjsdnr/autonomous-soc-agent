"""Stable capability and risk declarations, not execution authorization."""

from enum import StrEnum


class ToolPermission(StrEnum):
    SYSTEM_READ = "system_read"
    NETWORK_READ = "network_read"
    FILE_READ = "file_read"
    SYSTEM_WRITE = "system_write"
    NETWORK_WRITE = "network_write"
    FILE_WRITE = "file_write"


class ToolRiskLevel(StrEnum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"
