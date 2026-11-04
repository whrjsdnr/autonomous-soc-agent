"""Real stores and status projection; only the Host reader is replaced."""

import json
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
