"""Opt-in retained-session GUI verification: read-only, no capture/replay/inference."""

import asyncio
import hashlib
import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.operational.network_capture.live_session import load_session
from soc_agent.security_ai.research.live_evidence import verify
from soc_agent.security_ai.research.live_service import LiveMonitoring, LiveResearch
from soc_agent.security_ai.research.models import digest
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths


def file_hashes(directory):
    return {
        str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


@pytest.mark.asyncio
async def test_selected_native_session_retained_gui_and_readonly_reopen(tmp_path):
    requested = os.environ.get("SOC_NATIVE_SESSION_VERIFY_DIRECTORY")
    if requested is None:
        pytest.skip("Explicit retained-session path required; never selects or collects live data")
    directory = Path(requested).absolute()
    before = file_hashes(directory)
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs/linux-soc-v1/live-network-native-session-evidence.json"
        ).read_text()
    )
    claimed = manifest.pop("manifest_digest")
    assert digest(manifest) == claimed
    saved = verify(directory)
    assert saved["session_id"] == manifest["session_id"]
    assert saved["packets"] == manifest["persistence"]["packets"] == 256
    assert saved["flows"] == manifest["persistence"]["flows"] == 4
    assert saved["queue"] == manifest["persistence"]["queue"] == {"DONE": 260}
    assert saved["database_sha256"] == manifest["database_sha256"]
    assert saved["audit_digest"] == manifest["audit"]["runtime_head"]
    assert saved["capture_status"] == "CAPTURE_VERIFIED"
    assert saved["persistence_status"] == "PERSISTENCE_VERIFIED"
    assert saved["finalization"] == "VERIFIED" and saved["models"] == []
    assert saved["status"] == "PARTIAL"

    def retained(scope):
        # Explicit test composition selects exactly this stored session. No start(),
        # helper socket, automatic latest-session selection or database recovery.
        owner = LiveMonitoring(scope, paths=research_paths())
        owner.directory = directory
        owner.session = load_session(directory)
        owner.demo = LiveResearch(directory, paths=research_paths())
        owner.state = "RETAINED_SESSION_NOT_LIVE"
        return owner

    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "isolated-gui"))
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[0].__name__)
    try:
        await idle(root, app)

        async def attach_readonly():
            app.worker.backend.live_monitoring = retained(tmp_path / "scope")

        await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(attach_readonly(), app.worker.loop)
        )
        app.navigate("Live Network")
        deadline = time.monotonic() + 10
        while app.live_view.last_snapshot.get("session_id") != saved["session_id"]:
            if time.monotonic() >= deadline:
                raise AssertionError("RETAINED_GUI_SNAPSHOT_NOT_RENDERED")
            root.update()
            await asyncio.sleep(0.02)
        view = app.live_view
        snapshot = view.last_snapshot
        network = snapshot["network"]
        assert view.session == saved["session_id"]
        assert snapshot["state"] == "RETAINED_SESSION_NOT_LIVE"
        assert not snapshot["collection_live"] and not snapshot["listener_ready"]
        assert snapshot["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
        assert snapshot["write_policy"] == "WRITE_DENIED"
        assert snapshot["last_error"] is None
        assert network["capture_generation"] == saved["session_id"]
        assert network["finalization"] == "VERIFIED"
        assert network["packets_collected"] == 256 and network["flow_records"] == 4
        assert network["capture_drops"] == 0 and network["gap_count"] == 1
        assert network["queue_backlog"] == 0 and network["transport_queue_depth"] == 0
        assert not network["transport_reader_running"]
        assert network["packets_per_second"] is None and network["flows_per_minute"] is None
        assert not view.command and not app.current_records
        assert not snapshot["research"]["worker_running"]
        for profile in ("quality", "edge"):
            metrics = snapshot["research"]["model_metrics"][profile]
            assert metrics["successful"] == metrics["unknown"] == 0
            assert metrics["last_inference"] is None and metrics["state"] == "IDLE"
        text = view.metrics.get()
        for expected in (
            "Packets 256",
            "Flows 4",
            "Drops 0",
            "Gaps 1",
            "Queue 0",
            "quality: IDLE / confirmed 0 / unknown 0",
            "edge: IDLE / confirmed 0 / unknown 0",
            "Audit VERIFIED",
            "Last error NONE_RECORDED",
        ):
            assert expected in text
        for width, height in [(1920, 1080), (1366, 768)]:
            root.geometry(f"{width}x{height}")
            root.update()
            assert root.winfo_ismapped() and view.metrics.get() == text
        reopened = retained(tmp_path / "reopened-scope").snapshot()
        assert reopened["session_id"] == snapshot["session_id"]
        assert reopened["research"]["records"] == snapshot["research"]["records"] == []
        assert reopened["network"] == network
        assert not reopened["collection_live"] and not errors
    finally:
        await close(root, app)
    assert file_hashes(directory) == before
