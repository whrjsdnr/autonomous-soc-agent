"""Explicit WSLg tests: actual Tk windows and kernel socket, fixtures for controlled actions."""

import asyncio
import gc
import os
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import SCREENS, Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED
from tests.gui_screen_capture import capture
from tests.integration.restricted_response.test_executor import endpoint


@pytest.fixture(autouse=True)
def release_display_objects_on_creator_thread():
    """Tk interpreters from completed tests must not be finalized by the next worker's GC."""
    owner = threading.get_ident()
    yield
    assert threading.get_ident() == owner
    gc.collect()


async def idle(root, app, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        root.update()
        await asyncio.sleep(0.02)
        if not app.busy:
            root.update()
            if not app.busy:
                return
    raise AssertionError("GUI action timed out")


async def close(root, app):
    app.close()
    for _ in range(300):
        if not app.worker.thread.is_alive():
            return
        root.update()
        await asyncio.sleep(0.02)
    raise AssertionError("GUI worker did not close")


@pytest.mark.asyncio
async def test_actual_windows_scenarios_and_resizing(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        callback_threads = []
        app.call("dashboard", callback=lambda _: callback_threads.append(threading.get_ident()))
        await idle(root, app)
        assert callback_threads == [threading.get_ident()]
        for screen in SCREENS:
            app.navigate(screen)
            await idle(root, app)
            assert app.title.cget("text") == screen and root.winfo_ismapped()
        assert len(app.tree.get_children()) == 12
        app.run_scenario(all_scenarios=True)
        end = time.monotonic() + 120
        while len(app.result_by_scenario) < 12 and time.monotonic() < end:
            root.update()
            await asyncio.sleep(0.02)
        assert len(app.result_by_scenario) == 12
        assert all(v["overall_status"] == "PASS" for v in app.result_by_scenario.values())
        if os.getenv("SOC_GUI_SCREENSHOTS"):
            capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / "scenario-fixture.png")
        root.geometry("1150x740")
        root.update()
        assert root.winfo_width() == 1150
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_actual_gui_peer_approval_reject_marker_rollback_and_no_external_stop(
    tmp_path, monkeypatch
):
    async with endpoint(tmp_path, monkeypatch) as (directory, monitor, finding, _, _):
        monitor.simulation.set_enabled(True)
        monitor.simulation.prepare_completed()
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / "gui", runtime_directory=directory, source_label="FIXTURE"
            ),
        )
        monkeypatch.setattr("soc_agent.gui.app.messagebox.askyesno", lambda *args, **kwargs: True)
        monkeypatch.setattr(
            "soc_agent.gui.app.simpledialog.askstring", lambda *args, **kwargs: finding
        )
        try:
            await idle(root, app)
            app.navigate("Investigations")
            await idle(root, app)
            assert app.current_records
            if os.getenv("SOC_GUI_SCREENSHOTS"):
                capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / "investigation-fixture.png")
            app.navigate("Response & Approval")
            await idle(root, app)
            assert app.current_records
            app.tree.selection_set("0")
            root.update()
            app.response_action("approve")
            await idle(root, app)
            assert app.selected_result["status"] == "APPROVED"
            app.response_action("execute")
            await idle(root, app)
            assert app.selected_result["status"] == "SIMULATED"
            app.operation("simulation-records")
            await idle(root, app)
            pending = next(
                i for i, v in enumerate(app.current_records) if v["status"] == "PENDING_APPROVAL"
            )
            app.tree.selection_set(str(pending))
            root.update()
            app.response_action("reject")
            await idle(root, app)
            assert app.selected_result["status"] == "REJECTED"
            app.response_kind.set("restricted")
            app.response_action("request")
            await idle(root, app)
            assert app.selected_result["status"] == "PENDING_APPROVAL"
            app.response_action("approve")
            await idle(root, app)
            app.response_action("execute")
            await idle(root, app)
            assert app.selected_result["status"] == "TEST_RESOURCE_CHANGED"
            assert (directory / "test-resources/marker").read_bytes() == QUARANTINED
            app.response_action("rollback-request")
            await idle(root, app)
            app.response_action("approve")
            await idle(root, app)
            app.response_action("execute")
            await idle(root, app)
            assert app.selected_result["status"] == "ROLLED_BACK"
            assert (directory / "test-resources/marker").read_bytes() == AVAILABLE
            if os.getenv("SOC_GUI_SCREENSHOTS"):
                app.notice.set("FIXTURE authentication · OS peer UID test · registered marker only")
                capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / "approval-fixture.png")
            state = monitor.store.state()
        finally:
            await close(root, app)
        assert monitor.store.state() == state


def test_actual_module_command_duplicate_and_graceful_sigterm(tmp_path):
    command = [sys.executable, "-m", "soc_agent.gui", "--data-directory", str(tmp_path / "launch")]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(1)
        assert child.poll() is None
        duplicate = subprocess.run(command, capture_output=True, timeout=15)
        assert duplicate.returncode == 1 and b"BLOCKED" in duplicate.stderr
        child.send_signal(signal.SIGTERM)
        _, errors = child.communicate(timeout=30)
        assert child.returncode == 0, errors
    finally:
        if child.poll() is None:
            child.terminate()
            child.communicate(timeout=30)


@pytest.mark.asyncio
async def test_chart_changes_follow_actual_fixture_queue(tmp_path, monkeypatch):
    from soc_agent.security_ai.operational.native_authentication import project_journal
    from tests.integration.linux_runtime.test_monitor import setup
    from tests.unit.operational_features.test_native_authentication import row

    directory, monitor = setup(tmp_path, monkeypatch)
    await monitor.tick()
    root = tk.Tk()
    app = Desktop(
        root,
        GUIConfig(
            data_directory=tmp_path / "chart-gui",
            runtime_directory=directory,
            source_label="FIXTURE",
        ),
    )
    try:
        await idle(root, app)
        observed = []
        for round_id in range(3):
            for i in range(4):
                index = 100 + round_id * 4 + i
                event = project_journal(
                    row(
                        index,
                        4 + round_id * 4 + i,
                        "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2",
                    ),
                    include_pam_failures=True,
                )
                monitor.pipeline.queue.enqueue(event)
            app.refresh()
            await idle(root, app)
            observed.append(app.history.samples[-1].queue)
            for _ in range(4):
                monitor.pipeline.step()
            # A scheduled periodic read may still carry the earlier queue snapshot.
            await idle(root, app)
            app.refresh()
            await idle(root, app)
            observed.append(app.history.samples[-1].queue)
        assert observed == [4, 0, 4, 0, 4, 0]
        completed_before = app.history.samples[-1].completed
        await monitor.investigate_one()
        app.refresh()
        await idle(root, app)
        assert app.history.samples[-1].completed == completed_before + 1
        assert app.trends[1].find_withtag("series-completed")
        assert app.trends[0].find_withtag("series-queue")
        before = app.trends[0].coords(app.trends[0].find_withtag("series-queue")[0])
        root.geometry("1200x800")
        root.update()
        after = app.trends[0].coords(app.trends[0].find_withtag("series-queue")[0])
        assert before != after
        if os.getenv("SOC_GUI_SCREENSHOTS"):
            app.notice.set(
                "FIXTURE · measured queue 4 → 0 × 3 · investigation count increased · no animation"
            )
            capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / "queue-trend-fixture.png")
            from tests.gui_visual_checks import screenshot_sizes

            await screenshot_sizes(root, app, "queue-store-fixture")
        app.render_dashboard({"metric_scope": "different-store", "queue_backlog": 2})
        assert len(app.history.samples) == 1
        assert app.history.samples[-1].completed is None
        assert not app.trends[1].find_withtag("series-completed")
    finally:
        await close(root, app)
