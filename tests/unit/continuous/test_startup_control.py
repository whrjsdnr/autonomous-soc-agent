"""Startup publication is independent of durable investigation initialization."""

import asyncio
import json
import threading

import pytest
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.continuous.service import ContinuousRuntime


@pytest.mark.asyncio
async def test_control_identity_and_stop_exist_while_investigation_initialization_is_blocked(
    tmp_path, monkeypatch
):
    directory, _ = make(tmp_path)
    service = ContinuousRuntime(directory)
    entered, release = threading.Event(), threading.Event()
    original = InvestigationTasks.__init__

    def blocked(self, *args, **kwargs):
        entered.set()
        assert release.wait(12)
        original(self, *args, **kwargs)

    monkeypatch.setattr(InvestigationTasks, "__init__", blocked)
    task = asyncio.create_task(service.run())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.sleep(0.3)
        record = json.loads((directory / "observation.json").read_text())
        value = record["snapshot"]
        assert value["control"]["identity"] == service.control_identity
        assert value["state"] == "STARTING" and not value["collection_live"]
        assert value["startup"]["stage"] == "INVESTIGATION_STORAGE"
        assert service.analysis.process is None
        service.stop.set()
        await asyncio.sleep(0.15)
        assert not task.done()  # Read/write join is still required before cleanup.
    finally:
        release.set()
        service.stop.set()
        await asyncio.wait_for(task, 20)
    assert service.store.state()["state"] == "STOPPED"


def test_controller_import_does_not_load_inference_or_application():
    import os
    import subprocess
    import sys

    code = """
import sys
import soc_agent.cli
import soc_agent.continuous.cli
for name in ('numpy','sklearn','soc_agent.application','soc_agent.external_runtime',
             'soc_agent.security_ai.offline_workflow'):
    assert name not in sys.modules, name
"""
    child = subprocess.run(
        [sys.executable, "-c", code],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert child.returncode == 0, child.stderr


def test_feature_row_compatibility_alias_and_public_exports():
    from importlib import import_module

    from soc_agent.external_runtime import FeatureRow as legacy
    from soc_agent.security_ai.external.models import FeatureRow

    assert legacy is FeatureRow
    assert set(FeatureRow.model_fields) == {"event_id", "profiles", "observation"}
    for name in ("authentication", "network", "ingestion"):
        module = import_module(
            "soc_agent." + ("security_ai." if name != "ingestion" else "") + name
        )
        for exported in module.__all__:
            assert getattr(module, exported) is getattr(module, exported)
        with pytest.raises(AttributeError):
            _ = module.unsupported_attribute


@pytest.mark.asyncio
async def test_stop_before_durable_startup_finishes_never_starts_collector(tmp_path, monkeypatch):
    directory, _ = make(tmp_path)
    service = ContinuousRuntime(directory)
    entered, release = threading.Event(), threading.Event()
    original = service.store.control

    def control():
        entered.set()
        assert release.wait(12)
        original()

    async def forbidden():
        pytest.fail("collector started after startup STOP")
        if False:
            yield {}

    monkeypatch.setattr(service.store, "control", control)
    monkeypatch.setattr(service.source, "events", forbidden)
    task = asyncio.create_task(service.run())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        await asyncio.sleep(0.3)
        assert json.loads((directory / "observation.json").read_text())["snapshot"]["control"]
        service.stop.set()
    finally:
        release.set()
        service.stop.set()
        await asyncio.wait_for(task, 20)
    assert service.analysis.process is None
    assert service.store.state()["state"] == "STOPPED"


def test_audit_import_is_resolved_before_the_sqlite_write_lock(tmp_path, monkeypatch):
    import builtins
    import sqlite3

    directory, store = make(tmp_path)
    original = builtins.__import__
    checked = []

    def load(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "soc_agent.security_ai.external.runtime_store" and fromlist == ("audit",):
            with sqlite3.connect(directory / "service.sqlite", timeout=0) as connection:
                connection.execute("BEGIN EXCLUSIVE")
                connection.rollback()
            checked.append(True)
        return original(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", load)
    store.control()
    assert checked == [True]


def test_startup_identity_expiry_never_displays_current_liveness(tmp_path):
    from tests.unit.continuous.test_storage_control_isolation import control_snapshot

    from soc_agent.continuous.cli import observed_status

    directory, store = make(tmp_path)
    value = control_snapshot()
    value["state"] = "STARTING"
    value["control"]["monotonic"] -= 6
    store.update(value)
    result = observed_status(directory)
    assert result["state"] == "UNKNOWN_STALE_HEARTBEAT"
    assert result["collection_live"] is False


@pytest.mark.asyncio
async def test_control_observes_dns_created_after_control_start(tmp_path):
    from types import SimpleNamespace

    directory, _ = make(tmp_path)
    service = ContinuousRuntime(directory)
    task = asyncio.create_task(service.control())
    try:
        await asyncio.sleep(0.1)
        assert service.cached_dns_transport is None
        service.dns_source = SimpleNamespace(snapshot={"state": "READY", "counter": 7})
        async with asyncio.timeout(2):
            while service.cached_dns_transport is None:
                await asyncio.sleep(0.02)
        assert service.cached_dns_transport["counter"] == 7
    finally:
        service.stop.set()
        await task
