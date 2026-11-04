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


def test_command_signal_exit_is_distinguishable_from_source_error_without_host_access():
    import signal
    import sys

    with pytest.raises(collectors.CollectorUnavailable) as caught:
        collectors.bounded_command(
            [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]
        )
    assert collectors.collector_failure(caught.value) == "COMMAND_EXIT_NONZERO"
    observation = caught.value.command_observation
    assert observation.returncode == -signal.SIGTERM
    assert observation.finished_monotonic >= observation.started_monotonic
    assert observation.os_errno is None
    assert set(observation.model_dump()) == {
        "returncode",
        "os_errno",
        "started_monotonic",
        "finished_monotonic",
    }


def test_command_os_error_preserves_errno_without_command_or_payload(monkeypatch):
    import errno

    def unavailable(*args, **kwargs):
        raise OSError(errno.EAGAIN, "private command and source path")

    monkeypatch.setattr(collectors.subprocess, "run", unavailable)
    with pytest.raises(collectors.CollectorUnavailable) as caught:
        collectors.bounded_command(["private argv"])
    observation = caught.value.command_observation
    assert observation.os_errno == errno.EAGAIN
    assert observation.returncode is None
    assert "private" not in observation.model_dump_json()


@pytest.mark.parametrize(
    "payload",
    [
        {"started_monotonic": 2, "finished_monotonic": 1},
        {"started_monotonic": 1, "finished_monotonic": float("nan")},
        {"started_monotonic": 1, "finished_monotonic": 2, "returncode": "secret"},
        {"started_monotonic": 1, "finished_monotonic": 2, "stderr": "secret"},
    ],
)
def test_command_observation_rejects_invalid_or_sensitive_fields(payload):
    with pytest.raises(ValueError):
        collectors.CommandObservation.model_validate(payload)
