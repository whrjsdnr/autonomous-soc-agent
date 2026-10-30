"""Real Tk + independent ordinary service lifecycle; no Native or API calls."""

import asyncio
import hashlib
import json
import tkinter as tk

import pytest

from soc_agent.continuous.cli import main, start, status
from soc_agent.continuous.store import Store
from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_gui_detach_reconnect_and_owned_service_stop(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        json.dumps(
            dict(
                sequence=1,
                id="6a3fced6-dd7f-480e-9cb5-2f16b6b5a0ed",
                kind="excluded",
                affects_integrity=False,
            )
        )
        + "\n"
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            dict(
                source="JSONL_REPLAY",
                input_file=str(source),
                input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                heartbeat_seconds=0.1,
            )
        )
    )
    directory = tmp_path / "service"
    assert main(["init", str(directory), "--config", str(config)]) == 0
    launched = await asyncio.to_thread(start, directory)
    assert launched["status"] == "SERVICE_HEARTBEAT_VERIFIED"
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui1", continuous_directory=directory))
    try:
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        assert "JSONL_REPLAY" in app.continuous_summary.cget("text")
        assert "Runtime cleanup:" in app.continuous_summary.cget("text")
        assert "Collector cleanup: NOT_APPLICABLE_REPLAY" in app.continuous_summary.cget("text")
        with pytest.raises(BlockingIOError):
            await asyncio.to_thread(start, directory)
        await close(root, app)
        assert status(directory)["state"] == "RUNNING"
        root = tk.Tk()
        app = Desktop(
            root, GUIConfig(data_directory=tmp_path / "gui2", continuous_directory=directory)
        )
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        assert "Native live: False" in app.continuous_summary.cget("text")
    finally:
        await close(root, app)
        Store(directory).control(stop=True)
        for _ in range(100):
            if status(directory).get("state") == "STOPPED":
                break
            await asyncio.sleep(0.1)
    assert status(directory)["cleanup"] == "VERIFIED"


@pytest.mark.asyncio
async def test_verified_three_domain_incidents_and_investigation_in_gui(tmp_path):
    """SYNTHETIC/FIXTURE inputs, REAL_MODEL, SCRIPTED; imported results are never LIVE."""
    from datetime import UTC, datetime
    from pathlib import Path

    from soc_agent.continuous.authentication import AuthenticationWindows, normalized
    from soc_agent.gui.analysis_service import project_result
    from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
    from soc_agent.security_ai.research.environment import Paths
    from tests.integration.test_raw_dns_workflow import job, message
    from tests.unit.continuous.test_runtime import make, window
    from tests.unit.continuous.test_stream_integration import auth, packages

    ml = Path("/home/geonug/kdt-linux/ML")
    paths = Paths(
        ml,
        ml.parent / "autonomous-soc-agent/.security-ai-demo/inference/bin/python",
        Path(__file__).resolve().parents[1] / "src",
    )
    auths = AuthenticationWindows(packages(), origin="FIXTURE")
    for i in range(42):
        auths.observe(normalized(auth(i), "a" * 64)[1], source_digest="a" * 64)
    auth_job = auths.advance(datetime(2026, 1, 1, 0, 5, tzinfo=UTC), source_digest="a" * 64)[0]
    jobs = [window(), auth_job, job(message(), message(True, at=120))]
    recent = []
    for i, item in enumerate(jobs):
        output = tmp_path / f"outcome-{i}"
        await OfflineWorkflow(output, paths=paths).run(item)
        result = project_result(verify_result(output))
        recent.append(
            dict(
                incident_id=result["incident_id"],
                origins=result["input_origins"],
                domains=result["evidence_domains"],
                classification=result["classification"],
                eligibility=result["eligibility"],
                audit=result["audit"],
                output=str(output),
            )
        )
    directory, store = make(tmp_path)
    store.update(
        dict(
            state="STOPPED",
            collector="STOPPED",
            worker="STOPPED",
            cleanup="VERIFIED",
            collection_live=False,
            source="JSONL_REPLAY",
            recent_results=recent,
        )
    )
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", continuous_directory=directory))
    try:
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        values = [
            app.continuous_incidents.item(i, "values")
            for i in app.continuous_incidents.get_children()
        ]
        columns = list(app.continuous_incidents["columns"])
        assert {value[columns.index("domain")] for value in values} == {
            "NETWORK",
            "DNS",
            "AUTHENTICATION",
        }
        assert {value[columns.index("origin")] for value in values} == {"FIXTURE"}
        assert "Native live: False" in app.continuous_summary.cget("text")
        app.continuous_incidents.selection_set(recent[1]["incident_id"])
        for widget in app.content.winfo_children():
            try:
                if widget.cget("text") == "Inspect Selected Incident":
                    widget.invoke()
                    break
            except tk.TclError:
                continue
        await idle(root, app)
        shown = app.worker.backend.analysis_service.snapshot()["result"]
        assert shown["investigation_status"] == "COMPLETED_READ_ONLY"
        assert shown["llm_mode"] == "SCRIPTED" and shown["external_provider_calls"] == 0
        assert shown["evidence_domains"] == ["AUTHENTICATION"]
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_stale_native_and_cleanup_failure_health_display(tmp_path):
    """SYNTHETIC status snapshots, actual backend/Tk. Never a live Native claim."""
    import time

    from tests.unit.continuous.test_runtime import config, make

    directory = tmp_path / "native-status-fixture"
    store = Store.create(
        directory, config(tmp_path).model_copy(update={"source": "NATIVE_SERVICE"})
    )
    store.update(
        dict(
            state="RUNNING",
            collector="RUNNING",
            worker="ANALYZING",
            collection_live=True,
            source="NATIVE_SERVICE",
            heartbeat_unix=0,
        )
    )
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", continuous_directory=directory))
    try:
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        text = app.continuous_summary.cget("text")
        assert "UNKNOWN_STALE_HEARTBEAT" in text and "Native live: False" in text
        replay = tmp_path / "replay-status-fixture"
        replay.mkdir()
        directory, store = make(replay)
        store.update(
            dict(
                state="DEGRADED",
                source="JSONL_REPLAY",
                collector="STOPPED",
                worker="CIRCUIT_OPEN",
                collection_live=False,
                cleanup="UNVERIFIED",
                collector_cleanup="NOT_APPLICABLE_REPLAY",
                heartbeat_unix=time.time(),
                last_error="password=TEST_NOT_A_SECRET",
                metrics=dict(
                    packets=12, flows=2, eligible=1, incomplete=1, predictions=2, queue_dropped=3
                ),
                queue={"POISON": 1, "PENDING": 1},
            )
        )
        app.call("continuous_attach", str(directory), callback=app.continuous_updated)
        await idle(root, app)
        text = app.continuous_summary.cget("text")
        assert "Runtime cleanup: UNVERIFIED" in text and "CIRCUIT_OPEN" in text
        assert "Packets: 12" in text and "Eligible: 1" in text and "Drops: 3" in text
        assert "TEST_NOT_A_SECRET" not in text and "[REDACTED]" in text
        app.navigate("Dashboard")
        await idle(root, app)
        assert "Packets 12" in app.continuous_overview.cget("text")
        assert "Native live False" in app.continuous_overview.cget("text")
        app.navigate("System")
        await idle(root, app)
        assert "Runtime cleanup UNVERIFIED" in app.system.get("1.0", "end")
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_failed_tcx_stop_evidence_survives_gui_reconnect(tmp_path):
    """Stored FIXTURE status, real Tk/backend; a cleanup ACK is never capture proof."""
    import time

    from tests.unit.continuous.test_runtime import config

    directory = tmp_path / "tcx-cleanup-status-fixture"
    store = Store.create(
        directory, config(tmp_path).model_copy(update={"source": "NATIVE_SERVICE"})
    )
    store.update(
        dict(
            state="DEGRADED",
            source="NATIVE_SERVICE",
            collector="STOPPED",
            worker="STOPPED",
            collection_live=False,
            cleanup="UNVERIFIED",
            final_flush="VERIFIED",
            collector_cleanup="VERIFIED",
            heartbeat_unix=time.time(),
            last_error="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT",
            capture_window=dict(assessment=dict(status="UNKNOWN", reasons=["WINDOW_NOT_SEALED"])),
            producer=dict(
                cleanup_evidence=dict(
                    status="VERIFIED",
                    stop_ack=True,
                    seals=[dict(origin="FIXTURE")],
                    admission="BLOCKED_FAILED_STREAM",
                )
            ),
        )
    )
    for attempt in range(2):
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / f"gui-tcx-{attempt}",
                continuous_directory=directory,
            ),
        )
        try:
            await idle(root, app)
            app.navigate("Continuous")
            await idle(root, app)
            text = app.continuous_summary.cget("text")
            assert "TCX STOP ACK: True" in text and "Diagnostic seals: 1" in text
            assert "Capture: UNKNOWN" in text and "Native live: False" in text
            assert "Runtime cleanup: UNVERIFIED" in text
            assert "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT" in text
        finally:
            await close(root, app)
    assert store.state()["last_error"] == "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"
