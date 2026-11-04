"""No journal reads: command boundary failures retain only fixed public codes."""

import subprocess
from types import SimpleNamespace

import pytest

from soc_agent.realtime import collectors


@pytest.mark.parametrize(
    "fault,expected",
    [
        (PermissionError("private path"), "COMMAND_OS_ERROR"),
        (subprocess.TimeoutExpired(["secret"], 15), "COMMAND_TIMEOUT"),
        (3, "COMMAND_PERMISSION_DENIED"),
        (1, "COMMAND_EXIT_NONZERO"),
        (-9, "COMMAND_EXIT_NONZERO"),
        ("oversize", "COMMAND_OUTPUT_LIMIT"),
    ],
)
def test_safe_command_failure_categories(monkeypatch, fault, expected):
    def command(args, *, stdout, stderr, timeout, check):
        assert timeout == 15 and check is False
        stderr.write(b"private credentials and journal payload")
        if isinstance(fault, Exception):
            raise fault
        if fault == "oversize":
            stdout.seek(4 * 1024 * 1024)
            stdout.write(b"x")
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(returncode=fault)

    monkeypatch.setattr(collectors.subprocess, "run", command)
    with pytest.raises(collectors.CollectorUnavailable) as caught:
        collectors.bounded_command(["/fixture/journalctl"])
    assert collectors.collector_failure(caught.value) == expected
    assert "private" not in str(caught.value)


def test_unrecognized_error_text_and_code_never_cross_audit_boundary():
    error = collectors.CollectorUnavailable("private payload", failure_code="private payload")
    assert collectors.collector_failure(error) == "UNKNOWN"
