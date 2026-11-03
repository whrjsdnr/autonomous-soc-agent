"""Real collector/parser/stores/GUI with only journal availability and command mocked.

All journal rows are existing fixtures. No host log read, login, model or API run.
"""

import asyncio
import hashlib
import json
from uuid import UUID

import pytest
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.continuous.models import ContinuousConfig
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import LinuxMonitor, initialize
from soc_agent.realtime.collectors import CollectorUnavailable, LinuxJournalCollector
from soc_agent.security_ai.operational import native_authentication


def setup(tmp_path, monkeypatch, *, denied=False):
    calls = []
    rows = [
        row(i, i, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")
        for i in range(1, 4)
    ]

    def availability(self):
        self.command = "/fixture/journalctl"

    def command(arguments):
        calls.append(arguments)
        assert arguments[0] == "/fixture/journalctl"
        assert arguments[-4:] == ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", "+", "_COMM=sshd"]
        if denied:
            raise CollectorUnavailable("PERMISSION_DENIED:fixture")
        cursor = next((a.split("=", 1)[1] for a in arguments if a.startswith("--cursor=")), None)
        if cursor:
            return json.dumps(next(r for r in rows if r["__CURSOR"] == cursor)) + "\n"
        if any(a.startswith("--after-cursor=") for a in arguments):
            return ""
        assert "--lines=+16" in arguments
        return "\n".join(json.dumps(r) for r in rows) + "\n"

    monkeypatch.setattr(LinuxJournalCollector, "__init__", availability)
    monkeypatch.setattr(native_authentication, "bounded_command", command)
    auth = tmp_path / "auth"
    initialize(
        auth,
        RuntimeConfig(
            incident_id=UUID(int=55),
            repeated_failures=3,
            multiple_accounts=3,
            poll_seconds=0.2,
            assessment_mode="READ_ONLY",
        ),
    )
    source = tmp_path / "empty.jsonl"
    source.write_bytes(b"")
    continuous = tmp_path / "continuous"
    Store.create(
        continuous,
        ContinuousConfig(
            source="JSONL_REPLAY",
            input_file=source,
            input_sha256=hashlib.sha256(b"").hexdigest(),
            authentication_runtime=auth,
        ),
    )
    return auth, ContinuousRuntime(continuous), LinuxMonitor(auth), calls


@pytest.mark.asyncio
async def test_collector_to_queue_monitor_continuous_gui_and_reconnect(tmp_path, monkeypatch):
    auth, continuous, monitor, calls = setup(tmp_path, monkeypatch)
    task = asyncio.create_task(monitor.run(duration_seconds=3))
    desktop = Backend(GUIConfig(data_directory=tmp_path / "gui", runtime_directory=auth))
    reconnected = None
    try:
        for _ in range(40):
            if monitor.store.state()["last_collection"]:
                break
            await asyncio.sleep(0.05)
        snapshot = await continuous.observed_snapshot()
        assert snapshot["authentication"]["runtime_state"] == "RUNNING"
        value = (await desktop.production_status())["authentication"]
        assert value["runtime_state"] == "RUNNING" and value["authentication_events"] == 3
        assert len(value["recent_events"]) == 3
        assert "fixture-user" not in json.dumps(value) and "192.0.2.5" not in json.dumps(value)
        assert value["assessment_mode"] == "READ_ONLY" and not value["real_llm_enabled"]
        assert monitor.pipeline.queue.counts() == {"DONE": 3}
        assert sum(monitor.store.jobs().values()) == 2
        cursor = monitor.pipeline.queue.cursor(monitor.collector.identity)
        assert cursor is not None
        assert (await desktop.close())["external_runtime_untouched"]
        assert not task.done()
        reconnected = Backend(
            GUIConfig(data_directory=tmp_path / "gui-reconnect", runtime_directory=auth)
        )
        again = (await reconnected.production_status())["authentication"]
        assert again["runtime_state"] == "RUNNING" and again["authentication_events"] == 3
        assert monitor.pipeline.queue.cursor(monitor.collector.identity) == cursor
        assert calls and all("--output=json" in c for c in calls)
        assert monitor.store.verify_audit()
    finally:
        await desktop.close()
        if reconnected is not None:
            await reconnected.close()
        monitor.request_stop()
        await asyncio.wait_for(task, 6)
    assert monitor.store.state()["state"] == "STOPPED"
    assert monitor.store.state()["last_error"] is None
    assert monitor.pipeline.queue.counts() == {"DONE": 3}
    assert (await continuous.observed_snapshot())["authentication"]["runtime_state"] == "STOPPED"


@pytest.mark.asyncio
async def test_permission_denial_is_visible_without_reset_or_fake_running(tmp_path, monkeypatch):
    auth, continuous, monitor, calls = setup(tmp_path, monkeypatch, denied=True)
    with pytest.raises(ValueError, match="PERMISSION_DENIED"):
        await monitor.run(duration_seconds=1)
    snapshot = await continuous.observed_snapshot()
    assert snapshot["authentication"]["runtime_state"] == "FAILED"
    assert snapshot["authentication"]["collector_state"] == "PERMISSION_DENIED"
    assert monitor.pipeline.queue.counts() == {}
    assert monitor.pipeline.queue.cursor(monitor.collector.identity) is None
    assert monitor.store.verify_audit() and len(calls) == 1
