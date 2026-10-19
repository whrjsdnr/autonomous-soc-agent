"""Shared display-only redaction; independent of runtime/database composition."""

import re

SENSITIVE = {
    "raw_data",
    "raw_payload",
    "feature_payload",
    "api_key",
    "authorization",
    "password",
    "token",
    "credential",
    "env_file",
    "message",
    "messages",
}


def display_data(value):
    """Untrusted backend text is display-only. Raw source/credential fields stay hidden."""
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]" if str(k).lower() in SENSITIVE else display_data(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [display_data(v) for v in value[:512]]
    if isinstance(value, str):
        value = re.sub(
            r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{25,})", "[REDACTED]", value
        )
        value = re.sub(
            r'(?i)(authorization|api[_-]?key|password|token)["\']?\s*[:=]\s*.*',
            r"\1=[REDACTED]",
            value,
        )
        return value[:24000]
    return value
