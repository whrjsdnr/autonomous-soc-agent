"""Actual WSLg UX and native artifacts. No packet capture, traffic or security WRITE."""

import asyncio
import hashlib
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.insights import measured_receipts, stamp
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


def find_button(parent, title):
    for child in parent.winfo_children():
        if child.winfo_class() == "TButton" and child.cget("text") == title:
            return child
        found = find_button(child, title)
        if found is not None:
            return found
    return None


async def scroll_to(root, app, widget):
    root.update()
    y = widget.winfo_rooty() - app.content.winfo_rooty()
    app.content_canvas.yview_moveto(max(0, y - 8) / max(1, app.content.winfo_height()))
    root.update()
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_actual_one_click_native_demo_layout_audit_and_restart(tmp_path):
    shots = Path(os.environ.get("SOC_GUI_SCREENSHOTS", tmp_path / "screens"))
    shots.mkdir(parents=True, exist_ok=True)
    runtime = (
        Path(os.environ["SOC_UNIFIED_AUTH_RUNTIME"])
        if os.environ.get("SOC_UNIFIED_AUTH_RUNTIME")
        else None
    )
    dbs = list(runtime.rglob("*.sqlite")) if runtime else []
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in dbs}
    config = GUIConfig(data_directory=tmp_path / "gui", runtime_directory=runtime)
    root = tk.Tk()
    app = Desktop(root, config)
    callbacks = []
    root.report_callback_exception = lambda *a: callbacks.append(a[0].__name__)
    measured = []
    try:
        from soc_agent.gui.typography import typography

        typography(root).photo("보안 관제 · 승인 기반 대응 · 조사 / 감사 0123456789", width=600)
        assert typography(root).last_unknown_glyphs == 0
        await idle(root, app)
        app.navigate("Dashboard")
        await idle(root, app)
        root.geometry("1920x1080")
        root.update()
        await asyncio.sleep(0.2)
        assert app.last_dashboard["research"]["inference_counts"] == {"quality": 0, "edge": 0}
        assert not app.unified_panel.dns.find_withtag("measured-point")
        capture(root, shots / "initial-dashboard-1920.png")
        app.navigate("Network Research")
        await idle(root, app)
        view = app.research_view
        assert view.last_snapshot["demo_state"] == "STOPPED"
        assert view.replay_button.instate(["!disabled"])
        root.focus_force()
        # WSLg grants top-level focus asynchronously; wait for the actual event,
        # rather than assuming one update() round has received the WM response.
        deadline = time.monotonic() + 3
        while root.focus_displayof() is None and time.monotonic() < deadline:
            root.update()
            await asyncio.sleep(0.02)
        assert root.focus_displayof() is not None
        view.replay_button.focus_set()
        deadline = time.monotonic() + 3
        while root.focus_get() != view.replay_button and time.monotonic() < deadline:
            root.update()
            await asyncio.sleep(0.02)
        assert root.focus_get() == view.replay_button
        view.replay_button.event_generate("<Tab>")
        deadline = time.monotonic() + 3
        while root.focus_get() == view.replay_button and time.monotonic() < deadline:
            root.update()
            await asyncio.sleep(0.02)
        assert root.focus_get() is not None and root.focus_get() != view.replay_button
        # One explicit Run click composes the existing prepare + replay operations.
        for flow in ("1", "3"):
            view.flow.set(flow)
            view.replay_button.invoke()
            view.replay()  # Duplicate user click while busy must not dispatch another request.
            ticks = 0
            deadline = time.monotonic() + 120
            while app.busy and time.monotonic() < deadline:
                root.update()
                await asyncio.sleep(0.02)
                ticks += 1
            await idle(root, app, timeout=120)
            assert ticks > 10, "No responsive UI loop during the real model request"
            measured.append((view.profile.get(), ticks))
        r = view.last_snapshot
        assert r["inference_counts"] == {"quality": 2, "edge": 2}
        assert len(view.trend.find_withtag("replay-point")) == 2
        assert [p["packet_count"] for p in view.trend.rows] == [2, 6]
        capture(root, shots / "network-research.png")
        view.selection.set("DNS · Security")
        view.choose_model()
        assert view.profile.get() == "dns" and tuple(view.input_box.cget("values")) == ("1", "2")
        assert "FIXTURE" in view.origin.get() and "UNVERIFIED" in view.origin.get()
        seen = False
        for flow in ("1", "2"):
            view.flow.set(flow)
            view.replay_button.invoke()
            deadline = time.monotonic() + 120
            while app.busy and time.monotonic() < deadline:
                root.update()
                await asyncio.sleep(0.02)
                seen |= bool(getattr(view, "last_activity", {}).get("worker_running"))
            await idle(root, app, timeout=120)
        assert seen
        r = view.last_snapshot
        assert r["dns_inference_count"] == 2 and len(r["records"]) == 6
        assert all(record["status"] == "COMPLETE" for record in r["records"])
        assert len(view.dns_chart.find_withtag("measured-point")) == 2
        assert [v for _, v in view.dns_chart.points] == [0.55859375, 0.0]
        assert not app.worker.backend.research_activity()["worker_running"]
        capture(root, shots / "dns-research.png")
        app.tree.selection_set(str(len(app.current_records) - 1))
        root.update()
        find_button(app.content, "Investigation").invoke()
        assert app.last_details["research_view"] == "investigation"
        await scroll_to(root, app, app.summary_frame)
        capture(root, shots / "research-investigation.png")
        research_db = app.config.data_directory / "network-research/soc/external-validation.sqlite"
        digest_before = hashlib.sha256(research_db.read_bytes()).hexdigest()
        find_button(app.content, "Audit / receipt").invoke()
        assert app.last_details["audit_integrity"] == "VERIFIED"
        assert app.last_details["research_view"] == "audit"
        await scroll_to(root, app, app.summary_frame)
        capture(root, shots / "audit.png")
        assert hashlib.sha256(research_db.read_bytes()).hexdigest() == digest_before
        app.copy_reference(digest=True)
        assert len(root.clipboard_get()) == 64
        app.navigate("Dashboard")
        await idle(root, app)
        receipts = measured_receipts(app.last_dashboard["research"])
        assert len(receipts) == 6
        assert len(app.unified_panel.invocations.find_withtag("invocation-point")) == 6
        assert len(app.unified_panel.latency.models) == 3
        assert app.unified_panel.dns.points == [
            (stamp(p["inferred_at"])[:8], p["score"]) for p in receipts if p["profile"] == "dns"
        ]
        for w, h in [(1920, 1080), (1366, 768), (1280, 720)]:
            root.geometry(f"{w}x{h}")
            root.update()
            await asyncio.sleep(0.2)
            assert len(app.unified_panel.status.items) == 8
            canvas = app.unified_panel.status
            assert canvas.bbox("all")[2] <= canvas.winfo_width() + 1
            for card in app.unified_panel.card_widgets.values():
                assert card.bbox("all")[2] <= card.winfo_width() + 1
            assert canvas.winfo_rooty() + canvas.winfo_height() < root.winfo_rooty() + h
            capture(root, shots / f"dashboard-{w}.png")
        original_scaling = root.tk.call("tk", "scaling")
        for factor in (1.0, 1.5):
            root.tk.call("tk", "scaling", factor)
            root.update()
            assert (
                app.unified_panel.status.bbox("all")[2]
                <= app.unified_panel.status.winfo_width() + 1
            )
        root.tk.call("tk", "scaling", original_scaling)
        root.geometry("1920x1080")
        root.update()
        if runtime:
            app.navigate("Investigations")
            await idle(root, app)
            assert app.current_records and app.current_records[0]["origin"] == "NATIVE_OS"
            app.tree.selection_set("0")
            root.update()
            capture(root, shots / "investigation.png")
        assert not callbacks, callbacks
    finally:
        await close(root, app)
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == d for p, d in before.items())
    original_ids = {rec["receipt"]["invocation_id"] for rec in r["records"]}
    root = tk.Tk()
    app = Desktop(root, config)
    try:
        await idle(root, app)
        app.navigate("Network Research")
        await idle(root, app)
        view = app.research_view
        recovered = view.last_snapshot
        assert recovered["demo_state"] == "STOPPED" and not recovered["worker_running"]
        assert recovered["audit_integrity"] == "VERIFIED" and recovered["dns_inference_count"] == 2
        assert {x["receipt"]["invocation_id"] for x in recovered["records"]} == original_ids
        view.replay_button.invoke()
        await idle(root, app, timeout=90)
        assert "no new inference" in view.progress.get()
        assert view.last_snapshot["inference_counts"] == {"quality": 2, "edge": 2}
        view.stop_button.invoke()
        await idle(root, app)
        assert view.last_snapshot["demo_state"] == "STOPPED"
    finally:
        await close(root, app)
    assert all(hashlib.sha256(p.read_bytes()).hexdigest() == d for p, d in before.items())
