"""Explicit WSLg/native backend validation. Never discovered as a default fixture test."""

import asyncio
import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.improvement_review.models import ReviewDecision
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop
from soc_agent.linux_runtime.operator import OperatorServer, operator_request
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.runtime_lock import exclusive_runtime_lock
from tests.gui_screen_capture import capture
from tests.gui_visual_checks import screenshot_sizes
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.integration.feedback_loop.test_loop import prepared, submit


def screenshot(root, name):
    if os.getenv("SOC_GUI_SCREENSHOTS"):
        capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / name)


@pytest.mark.asyncio
async def test_native_models_and_actual_model_view(tmp_path, monkeypatch):
    config = GUIConfig(
        data_directory=tmp_path / "gui",
        artifacts=Path(os.environ["SOC_EXTERNAL_ARTIFACT_ROOT"]),
        native_python=Path(os.environ["SOC_EXTERNAL_INFERENCE_PYTHON"]),
        source_label="FIXTURE",
    )
    root = tk.Tk()
    app = Desktop(root, config)
    monkeypatch.setattr("soc_agent.gui.app.messagebox.askyesno", lambda *a, **kw: True)
    try:
        await idle(root, app)
        app.navigate("Security AI Models")
        await idle(root, app)
        assert all(p["demo_inference"] == "UNKNOWN" for p in app.current_records[:3])
        app.model_probe()
        await idle(root, app, timeout=180)
        assert app.last_probe is not None, app.notice.get()
        probe = app.last_probe
        assert probe["model_results"] == 3 and probe["correlation_groups"] == 2
        assert probe["operational_input"] == "NOT_INFERABLE"
        assert probe["llm_provider_calls"] == 0 and probe["os_security_changes"] == 0
        app.refresh()
        await idle(root, app)
        visible = [app.tree.item(str(i), "values") for i in range(3)]
        assert all("VERIFIED (prior Fixture)" in row for row in visible), (visible, probe)
        app.notice.set(
            "ACTUAL native models · SYNTHETIC features · SCRIPTED assessment · advisory only"
        )
        screenshot(root, "models-native-fixture.png")
        assert all("VERIFIED (prior Fixture)" in str(row) for row in app.model_cards[:3])
        await screenshot_sizes(root, app, "models-native-fixture")
        (tmp_path / "native-result.json").write_text(json.dumps(probe, indent=2))
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_actual_wsl_owned_runtime_start_collect_restart_and_gui_close(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", source_label="LIVE_WSL"))
    directory = tmp_path / "live-runtime"
    try:
        await idle(root, app)
        app.call("initialize_runtime", directory, 5, 3, "READ_ONLY")
        await idle(root, app)
        assert directory.is_dir()
        app.call("start")
        await idle(root, app)
        started = time.monotonic()
        end = started + 35
        while time.monotonic() < end:
            app.refresh()
            await idle(root, app)
            root.update()
            await asyncio.sleep(1)
        snapshot = await asyncio.wrap_future(app.worker.submit("dashboard"))
        state = RuntimeStore(directory).state()
        assert state["state"] == "RUNNING" and state["last_collection"]
        assert state["cursor_health"] in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY")
        app.notice.set("LIVE_LINUX · existing WSL journal · READ_ONLY · no provider or OS response")
        screenshot(root, "dashboard-live-wsl.png")
        await screenshot_sizes(root, app, "dashboard-live-wsl")
        app.navigate("Investigations")
        await idle(root, app)
        real_rows = app.current_records
        assert all(r["origin"] != "FIXTURE" for r in real_rows)
        screenshot(root, "investigations-live-wsl.png")
        if app.current_records:
            app.tree.selection_set("0")
            root.update()
        await screenshot_sizes(root, app, "investigation-live-wsl")
        app.call("stop")
        await idle(root, app)
        assert RuntimeStore(directory).state()["state"] == "STOPPED"
        app.call("start")
        await idle(root, app)
        for _ in range(5):
            root.update()
            await asyncio.sleep(1)
        before_close = RuntimeStore(directory).state()
        assert before_close["cursor_health"] == "RESUMED_EXACT"
        (tmp_path / "live-result.json").write_text(
            json.dumps(
                {
                    "elapsed_before_restart_seconds": time.monotonic() - started,
                    "finding_count": len(real_rows),
                    "cursor": before_close["cursor_health"],
                    "authentication_records": snapshot["authentication_events"],
                    "queue_backlog": snapshot["queue_backlog"],
                    "completed_read_only": snapshot["completed_read_only"],
                },
                indent=2,
            )
        )
    finally:
        await close(root, app)
        child = app.worker.backend.child
        if child is not None and child.returncode is None:
            # User-started monitoring now deliberately outlives the GUI. The test
            # explicitly stops only its own Runtime after verifying the boundary.
            assert RuntimeStore(directory).state()["state"] == "RUNNING"
            stopped = await app.worker.backend.stop()
            assert stopped["status"] == "STOPPED"
    assert app.worker.backend.child.returncode == 0
    store = RuntimeStore(directory)
    assert store.state()["state"] == "STOPPED" and store.verify_audit()


@pytest.mark.asyncio
async def test_feedback_candidate_evaluation_visible_without_promotion(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (directory, monitor, ids):
        for identity in ids:
            assert (await submit(directory, monitor, identity))[0]["ok"]
        candidate = (await operator_request(directory, "candidates"))["result"]["candidates"][0]
    monitor = LinuxMonitor(directory)
    with exclusive_runtime_lock(directory / "writer.lock"):
        evaluation = RuntimeFeedbackLoop(monitor).evaluate(
            candidate["candidate_id"], repeated_failures=5, multiple_accounts=3
        )
    assert evaluation["verdict"] == "INCONCLUSIVE" and evaluation["promotion"] == "BLOCKED"
    server = OperatorServer(monitor, (os.geteuid(),))
    with exclusive_runtime_lock(directory / "writer.lock"):
        await server.start()
        review = await operator_request(
            directory,
            "candidate-review",
            candidate_id=candidate["candidate_id"],
            review_decision=ReviewDecision.DEFER,
            expected_evaluation=evaluation["evaluation_id"],
        )
        assert review["ok"]
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / "gui", runtime_directory=directory, source_label="FIXTURE"
            ),
        )
        try:
            await idle(root, app)
            app.navigate("Self-Improvement")
            await idle(root, app)
            app.operation("feedback-list")
            await idle(root, app)
            assert app.current_records
            app.operation("candidates")
            await idle(root, app)
            assert len(app.current_records) == 1
            assert app.current_records[0]["candidate_id"] == candidate["candidate_id"]
            with monitor.store.database.transaction(write=False) as c:
                before = tuple(c.iterdump())
            app.operation("evaluations")
            await idle(root, app)
            assert app.current_records[0]["verdict"] == "INCONCLUSIVE"
            assert app.current_records[0]["promotion"] == "BLOCKED"
            app.notice.set("FIXTURE feedback · offline result INCONCLUSIVE · promotion BLOCKED")
            screenshot(root, "self-improvement-fixture.png")
            assert app.improvement_chart.result["evaluation_id"] == evaluation["evaluation_id"]
            await screenshot_sizes(root, app, "self-improvement-fixture")
            app.operation("reviews")
            await idle(root, app)
            assert app.current_records[0]["status"] == "INCONCLUSIVE"
            with monitor.store.database.transaction(write=False) as c:
                assert tuple(c.iterdump()) == before
        finally:
            await close(root, app)
            await server.close()
