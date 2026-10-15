"""Actual mapped WSLg windows, real fixture stores and authenticated operator actions."""

import asyncio
import os
import threading
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import SCREENS, Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.components import HEALTHY
from soc_agent.gui.typography import typography
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.integration.restricted_response.test_executor import endpoint


async def settle(root):
    for _ in range(8):
        root.update()
        await asyncio.sleep(0.04)


async def screenshot_sizes(root, app, name):
    for width, height in ((1920, 1080), (1366, 768)):
        root.geometry(f"{width}x{height}+0+0")
        app.content_canvas.yview_moveto(0)
        await settle(root)
        assert (root.winfo_width(), root.winfo_height()) == (width, height)
        assert root.winfo_ismapped()
        if os.getenv("SOC_GUI_SCREENSHOTS"):
            capture(root, Path(os.environ["SOC_GUI_SCREENSHOTS"]) / f"{name}-{width}.png")


@pytest.mark.asyncio
async def test_visual_demo_journey_and_accessible_evidence(tmp_path, monkeypatch):
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
        monkeypatch.setattr("soc_agent.gui.app.messagebox.askyesno", lambda *a, **kw: True)
        monkeypatch.setattr("soc_agent.gui.app.simpledialog.askstring", lambda *a, **kw: finding)
        try:
            await idle(root, app)
            for name in SCREENS:
                app.navigate(name)
                await idle(root, app)
                assert app.title.cget("text") == name
            app.navigate("Dashboard")
            await idle(root, app)
            assert app.cards["collected_events"].get() == str(
                sum(monitor.pipeline.queue.counts().values())
            )
            assert app.last_dashboard["pending_approvals"] > 0
            assert app.hero.value["display_source"] == "FIXTURE"
            await screenshot_sizes(root, app, "dashboard-fixture")
            app.navigate("Scenario Demo")
            await idle(root, app)
            app.tree.selection_set("2")
            root.update()
            app.run_scenario()
            await idle(root, app)
            result = app.result_by_scenario["S03"]
            assert result["overall_status"] == "PASS" and result["input_origin"] == "FIXTURE"
            assert result["stages"]["investigation"]["status"] == "PASS"
            app.copy_reference(digest=True)
            assert root.clipboard_get() == result["audit_receipt"]
            await screenshot_sizes(root, app, "scenario-s03-fixture")
            app.navigate("Investigations")
            await idle(root, app)
            app.tree.selection_set("0")
            root.update()
            assert app.selected_result["evidence_references"] and not app.raw_visible
            assert app.selected_result["tool_steps"]
            app.copy_reference(digest=True)
            assert root.clipboard_get() == app.selected_result["result_digest"]
            app.toggle_raw()
            root.update()
            assert app.raw_container.winfo_ismapped()
            app.toggle_raw()
            root.update()
            assert not app.raw_container.winfo_ismapped()
            await screenshot_sizes(root, app, "investigation-fixture")
            app.navigate("Response & Approval")
            await idle(root, app)
            app.tree.selection_set("0")
            root.update()
            assert "disabled" in app.response_buttons["execute"].state()
            app.response_buttons["approve"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "APPROVED"
            app.response_buttons["execute"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "SIMULATED"
            app.operation("simulation-records")
            await idle(root, app)
            key = next(
                str(i)
                for i, r in enumerate(app.current_records)
                if r["status"] == "PENDING_APPROVAL"
            )
            app.tree.selection_set(key)
            root.update()
            app.response_buttons["reject"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "REJECTED"
            app.response_kind.set("restricted")
            app._change_response_mode()
            await idle(root, app)
            app.response_buttons["request"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "PENDING_APPROVAL"
            assert "disabled" in app.response_buttons["rollback-request"].state()
            app.response_buttons["approve"].invoke()
            await idle(root, app)
            app.response_buttons["execute"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "TEST_RESOURCE_CHANGED"
            assert "disabled" not in app.response_buttons["rollback-request"].state()
            await screenshot_sizes(root, app, "restricted-marker-fixture")
            app.response_buttons["rollback-request"].invoke()
            await idle(root, app)
            app.response_buttons["approve"].invoke()
            await idle(root, app)
            app.response_buttons["execute"].invoke()
            await idle(root, app)
            assert app.selected_result["status"] == "ROLLED_BACK"
            await screenshot_sizes(root, app, "approval-rollback-fixture")
            assert monitor.store.verify_audit()
            app.navigate("Security AI Models")
            await idle(root, app)
            assert len(app.model_cards) == 4
            await screenshot_sizes(root, app, "models-inventory")
        finally:
            await close(root, app)


@pytest.mark.asyncio
async def test_actual_fonts_hover_keyboard_unknown_empty_large_data_and_single_poll(
    tmp_path, monkeypatch
):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        await settle(root)
        await idle(root, app)
        fonts = typography(root)
        small = fonts.photo("보안 관제 Security 123", 12)
        large = fonts.photo("보안 관제 Security 123", 32)
        assert fonts.last_unknown_glyphs == 0 and large.height() > small.height() * 1.7
        errors = []
        thread = threading.Thread(target=lambda: wrong_thread(fonts, errors))
        thread.start()
        thread.join()
        assert errors == ["TK_TEXT_THREAD_BOUNDARY"]
        app.render_dashboard(
            {"runtime_state": "STOPPED", "health": "HEALTHY", "readiness": "READY"}
        )
        indicator = app.hero.find_withtag("health-indicator")[0]
        assert app.hero.itemcget(indicator, "fill") != HEALTHY
        assert app.cards["queue_backlog"].get() == "UNKNOWN"
        app.distribution.update_counts({"DONE": 2})
        assert app.distribution.type(app.distribution.find_withtag("distribution-arc")[0]) == "oval"
        app.render_dashboard(
            {
                "metric_scope": "test",
                "queue_backlog": 4,
                "completed_read_only": 1,
                "completed_llm": 0,
                "completed_scripted": 0,
            }
        )
        app.render_dashboard(
            {
                "metric_scope": "test",
                "queue_backlog": 0,
                "completed_read_only": 2,
                "completed_llm": 0,
                "completed_scripted": 0,
            }
        )
        root.update()
        chart = app.trends[0]
        chart.event_generate("<Motion>", x=100, y=100, warp=True)
        root.update()
        assert chart.find_withtag("crosshair") and chart.find_withtag("tooltip")
        chart.focus_force()
        chart.event_generate("<Right>")
        root.update()
        assert chart.hover is not None
        await screenshot_sizes(root, app, "chart-interaction-fixture")
        app.navigate("Scenario Demo")
        await idle(root, app)
        app.tree.focus_force()
        app.tree.event_generate("<Down>")
        root.update()
        assert app.tree.selection() == ("0",)
        app.tree.event_generate("<Down>")
        root.update()
        assert app.tree.selection() == ("1",)
        for i in range(1000):
            app.tree.insert(
                "", "end", iid=str(i), values=(str(i), "Fixture metadata", "FIXTURE", "NOT_RUN")
            )
        root.update()
        assert len(app.tree.get_children()) == 1000
        # Rendering stays bounded to visible rows; no hidden 1000-image allocation.
        assert len(app.tree.text_images) < 150
        app.detail.configure(height=35)
        app.toggle_raw()
        root.geometry("1366x768")
        await settle(root)
        page_before = app.content_canvas.yview()
        app.tree.event_generate("<Button-5>")
        root.update()
        assert app.tree.yview()[0] > 0
        assert app.content_canvas.yview() == page_before
        app.navigate("Dashboard")
        await idle(root, app)
        backend = app.worker.backend
        original = backend.dashboard
        calls = []

        async def delayed():
            calls.append(1)
            await asyncio.sleep(0.15)
            return await original()

        monkeypatch.setattr(backend, "dashboard", delayed)
        app._poll()
        app._poll()
        app._poll()
        await idle(root, app)
        assert len(calls) == 1

        async def failure():
            raise TimeoutError()

        monkeypatch.setattr(backend, "dashboard", failure)
        app.refresh()
        await idle(root, app)
        assert (
            app.hero.value["runtime_state"] == "UNKNOWN"
            and app.hero.value["last_error"] == "TimeoutError"
        )
        await screenshot_sizes(root, app, "error-unknown")
    finally:
        await close(root, app)


def wrong_thread(fonts, errors):
    try:
        fonts.photo("must fail")
    except RuntimeError as error:
        errors.append(str(error))
