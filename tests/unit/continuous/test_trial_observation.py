"""Reviewed launcher predicates; no service control, journal or Root execution."""

import copy
import subprocess

import pytest

from soc_agent.continuous.process_identity import (
    authenticated_producer_ready,
    read_service_journal,
)


def snapshot():
    return dict(
        source="NATIVE_SERVICE",
        collector="RUNNING",
        state="RUNNING",
        producer=dict(namespace="net:[4026532232]", policy_sha256="a" * 64, generation=123),
        component_health=dict(collector_message_unix=99.5),
        heartbeat_unix=99.5,
    )


def ready(value, pin="a" * 64):
    return authenticated_producer_ready(
        value, policy_sha256=pin, namespace="net:[4026532232]", now=100
    )


def test_current_policy_is_ready_and_old_trial_pin_is_rejected():
    assert ready(snapshot())
    assert not ready(snapshot(), "b" * 64)
    assert not ready(snapshot(), "")
    value = snapshot()
    value["producer"]["policy_sha256"] = "b" * 64
    assert not ready(value)
    assert ready(value, "b" * 64)


@pytest.mark.parametrize(
    "field,value",
    [("namespace", "net:[1]"), ("generation", 0), ("generation", True), ("generation", "123")],
)
def test_ready_scope_and_generation_fail_closed(field, value):
    sample = snapshot()
    sample["producer"][field] = value
    assert not ready(sample)


@pytest.mark.parametrize("stamp", [None, True, 95, 101, float("nan"), float("inf")])
@pytest.mark.parametrize("field", ["heartbeat_unix", "collector_message_unix"])
def test_ready_missing_stale_future_or_invalid_heartbeat(stamp, field):
    sample = snapshot()
    target = sample if field == "heartbeat_unix" else sample["component_health"]
    target[field] = stamp
    before = copy.deepcopy(sample)
    assert not ready(sample)
    assert sample == before  # Never refresh the observed heartbeat.


@pytest.mark.parametrize("field", ["collector", "state", "source"])
def test_ready_requires_native_running_state(field):
    sample = snapshot()
    sample[field] = "STOPPED"
    assert not ready(sample)


def test_journal_uses_bounded_current_boot_tail_and_preserves_nonzero_exit():
    def run(args, **kwargs):
        assert args[0] == "/usr/bin/journalctl"
        assert "--boot=0" in args and "--lines=200" in args
        assert kwargs == dict(stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        return subprocess.CompletedProcess(args, 1, "partial", "permission denied")

    value = read_service_journal("soc-operations-runtime.service", "2026-10-30", run=run)
    assert value["returncode"] == 1 and value["stderr"] == "permission denied"
    assert value["completeness"] == "UNVERIFIED" and not value["timed_out"]


def test_journal_timeout_retains_partial_output_without_inventing_child_exit():
    def run(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 15, output=b"STOP received\n", stderr=b"delayed\n")

    value = read_service_journal("soc-operations-runtime.service", "2026-10-30", run=run)
    assert value["returncode"] is None and value["timed_out"]
    assert value["stdout"] == "STOP received\n" and value["stderr"] == "delayed\n"
    assert value["error"] == "JOURNAL_EVIDENCE_TIMEOUT"
    assert value["completeness"] == "PARTIAL_OR_UNKNOWN"


def test_journal_rejects_unowned_unit_before_execution():
    with pytest.raises(ValueError, match="TRIAL_JOURNAL_UNIT_SCOPE"):
        read_service_journal("unrelated.service", "2026-10-30", run=None)
