"""Real stores and status projection; only the Host reader is replaced."""

import json
import time
from types import SimpleNamespace

import pytest
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.linux_runtime.__main__ import status
from soc_agent.realtime.collectors import CollectorUnavailable
from soc_agent.security_ai.operational import native_authentication as native


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["COMMAND_EXIT_NONZERO", "COMMAND_TIMEOUT", "COMMAND_OS_ERROR"])
async def test_source_failure_survives_audit_and_gui_projection(tmp_path, monkeypatch, failure):
    root, monitor = setup(tmp_path, monkeypatch)

    def poll(*args, **kwargs):
        raise CollectorUnavailable("private journal message", failure_code=failure)

    monkeypatch.setattr(monitor.collector, "poll", poll)
    await monitor.tick()
    state = monitor.store.state()
    assert state["collector"] == "SOURCE_UNAVAILABLE"
    diagnostic = state["collection_diagnostic"]
    assert diagnostic["failure_code"] == failure
    assert diagnostic["finished_monotonic"] >= diagnostic["started_monotonic"]
    assert status(root)["collection_diagnostic"] == diagnostic
    assert status(root)["readiness"] == "NOT_READY"
    assert monitor.pipeline.queue.counts() == {}
    assert monitor.store.verify_audit()
    with monitor.store.database.transaction(write=False) as connection:
        payloads = [r[0] for r in connection.execute("SELECT payload FROM monitor_audit")]
    retry = next(json.loads(p) for p in payloads if json.loads(p)["kind"] == "COLLECTION_RETRY")
    assert retry["details"]["failure_code"] == failure
    assert "private journal" not in json.dumps(payloads)


def test_parser_rejection_is_not_reclassified_as_json_failure(monkeypatch):
    collector = object.__new__(native.LinuxAuthenticationCollector)
    collector.native = SimpleNamespace(command="/fixture/journalctl")
    collector.include_pam_failures = False
    monkeypatch.setattr(native, "bounded_command", lambda args: b'{"MESSAGE": [1, 2]}')
    from soc_agent.realtime.collectors import collector_failure

    with pytest.raises(CollectorUnavailable) as caught:
        collector.poll()
    assert collector_failure(caught.value) == "JOURNAL_RECORD_REJECTED"
    monkeypatch.setattr(native, "bounded_command", lambda args: b"broken json")
    with pytest.raises(CollectorUnavailable) as caught:
        collector.poll()
    assert collector_failure(caught.value) == "JOURNAL_JSON_REJECTED"


@pytest.mark.asyncio
async def test_termination_metadata_survives_health_store_audit_and_gui(tmp_path, monkeypatch):
    from soc_agent.realtime.collectors import CommandObservation

    root, monitor = setup(tmp_path, monkeypatch)
    observation = CommandObservation(
        started_monotonic=10.0,
        finished_monotonic=14.9,
        returncode=-15,
    )

    def terminated(*args, **kwargs):
        raise CollectorUnavailable(
            "unavailable",
            failure_code="COMMAND_EXIT_NONZERO",
            command_observation=observation,
        )

    monkeypatch.setattr(monitor.collector, "poll", terminated)
    await monitor.tick()
    diagnostic = status(root)["collection_diagnostic"]
    assert diagnostic["command_observation"] == observation.model_dump()
    assert status(root)["readiness"] == "NOT_READY"
    assert monitor.pipeline.queue.counts() == {}
    with monitor.store.database.transaction(write=False) as connection:
        events = [json.loads(r[0]) for r in connection.execute("SELECT payload FROM monitor_audit")]
    retry = next(e for e in events if e["kind"] == "COLLECTION_RETRY")
    assert retry["details"]["command_observation"]["returncode"] == -15
    assert monitor.store.verify_audit()
    # No signal attribution or fake source-health success is derived from returncode.
    assert monitor.store.state()["collector"] == "SOURCE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_empty_readable_journal_reaches_ready_and_ack_without_inference(
    tmp_path, monkeypatch
):
    from tests.integration.linux_runtime.test_managed_authentication_lifecycle import (
        approve_fixture,
        mock_journal_child,
        prepare,
    )

    from soc_agent.continuous.authentication_lifecycle import AuthenticationLifecycle

    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch, seconds=())
    child = AuthenticationLifecycle(store)
    try:
        await child.start()
        assert child.state == "RUNNING"
        diagnostic = child.snapshot()["managed_lifecycle"]["startup_diagnostic"]
        assert diagnostic["collector"] == "INITIAL_READ"
        assert diagnostic["identity_matches"]
        assert diagnostic["deadline_monotonic"] - diagnostic["spawned_monotonic"] == 5
        assert diagnostic["observed_monotonic"] <= diagnostic["deadline_monotonic"]
        assert status(child.directory)["queue_backlog"] == 0
    finally:
        await child.close()
    assert child.evidence["stop_ack"]
    assert child.evidence["cleanup"] == "VERIFIED"
    assert child.evidence["queue_counts"] == {}


@pytest.mark.asyncio
async def test_source_unavailable_can_be_a_stop_consequence_after_ready_timeout(
    tmp_path, monkeypatch
):
    from tests.integration.linux_runtime.test_managed_authentication_lifecycle import (
        approve_fixture,
        mock_journal_child,
        prepare,
    )

    from soc_agent.continuous.authentication_lifecycle import AuthenticationLifecycle

    store = prepare(tmp_path)
    approve_fixture(store)
    # Only the Journal boundary is held by an Event. The real five-second
    # admission deadline and owned child STOP/ACK/cleanup remain unchanged.
    mock_journal_child(monkeypatch, held_until_stop=True)
    child = AuthenticationLifecycle(store)
    try:
        with pytest.raises(ValueError, match="AUTHENTICATION_READY_TIMEOUT"):
            await child.start()
        timeout_observed = time.monotonic()
        assert child.state == "FAILED"
        assert child.startup_diagnostic["collector"] == "NOT_STARTED"
        assert (
            child.startup_diagnostic["deadline_monotonic"]
            - child.startup_diagnostic["spawned_monotonic"]
            == 5
        )
    finally:
        await child.close()

    trace = [
        json.loads(line)
        for line in (store.directory / "authentication-fixture-startup.jsonl")
        .read_text()
        .splitlines()
    ]
    stages = {row["stage"]: row["monotonic"] for row in trace}
    assert stages["JOURNAL_COMMAND_BEGIN"] < timeout_observed
    assert timeout_observed <= stages["STOP_RECEIVED"]
    assert stages["STOP_RECEIVED"] <= stages["JOURNAL_COMMAND_TERMINATED_AFTER_STOP"]
    observed = status(child.directory)
    assert child._read()["collector"] == "SOURCE_UNAVAILABLE"
    command = observed["collection_diagnostic"]["command_observation"]
    assert command["returncode"] == -15
    assert command["finished_monotonic"] >= stages["STOP_RECEIVED"]
    assert child.evidence["stop_ack"] and child.evidence["cleanup"] == "VERIFIED"
    assert child.evidence["queue_counts"] == {}
