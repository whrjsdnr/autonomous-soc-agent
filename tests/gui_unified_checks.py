"""Explicit WSLg windows, actual three models, retained WSL Authentication read-only."""

import asyncio
import hashlib
import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_unified_actual_models_authentication_and_restart(tmp_path):
    shots = Path(os.environ.get("SOC_GUI_SCREENSHOTS", tmp_path / "screens"))
    shots.mkdir(parents=True, exist_ok=True)
    runtime = (
        Path(os.environ["SOC_UNIFIED_AUTH_RUNTIME"])
        if os.environ.get("SOC_UNIFIED_AUTH_RUNTIME")
        else None
    )
    dbs = list(runtime.rglob("*.sqlite")) if runtime else []
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in dbs}
    config = GUIConfig(data_directory=tmp_path / "gui", runtime_directory=runtime)
    root = tk.Tk()
    app = Desktop(root, config)
    callbacks = []
    root.report_callback_exception = lambda *args: callbacks.append(args[0].__name__)
    from soc_agent.gui.typography import typography

    image = typography(root).photo("status line\n" * 10, width=400)
    assert image.height() > 14 * 4 and image.height() <= 14 * 32
    try:
        await idle(root, app)
        app.navigate("Dashboard")
        await idle(root, app)
        root.geometry("1920x1080")
        root.update()
        assert app.last_dashboard["research"]["dns_inference_count"] == 0
        capture(root, shots / "unified-before-1920.png")
        app.navigate("Network Research")
        await idle(root, app)
        app.research_view.start_button.invoke()
        await idle(root, app)
        for flow in ("1", "3"):
            app.research_view.flow.set(flow)
            app.research_view.replay_button.invoke()
            await idle(root, app, timeout=120)
        app.research_view.profile.set("dns")
        app.research_view.profile_changed()
        assert tuple(app.research_view.input_box.cget("values")) == ("1", "2")
        app.research_view.flow.set("1")
        app.research_view.replay_button.invoke()
        # Pump Tk while the owned worker runs; progress is backed by actual process state.
        seen = False
        for _ in range(500):
            root.update()
            await asyncio.sleep(0.02)
            seen |= bool(getattr(app.research_view, "last_activity", {}).get("worker_running"))
            if not app.busy:
                break
        assert seen
        await idle(root, app, timeout=120)
        app.research_view.flow.set("2")
        app.research_view.replay_button.invoke()
        await idle(root, app, timeout=120)
        r = app.research_view.last_snapshot
        assert r["dns_inference_count"] == 2 and r["inference_counts"] == {"quality": 2, "edge": 2}
        assert len(app.research_view.dns_chart.find_withtag("measured-point")) == 2
        assert all(x["status"] == "COMPLETE" for x in r["records"]), [
            (x["status"], x.get("error")) for x in r["records"]
        ]
        capture(root, shots / "unified-research-dns-1920.png")
        app.navigate("Dashboard")
        await idle(root, app)
        assert len(app.unified_panel.dns.find_withtag("measured-point")) == 2
        assert all("IDLE" in app.unified_panel.cards[p].get() for p in ("quality", "edge", "dns"))
        assert "FIXTURE_NATIVE_ONLY" in app.unified_panel.latest.get()
        capture(root, shots / "unified-dashboard-1920.png")
        root.geometry("1366x768")
        root.update()
        await asyncio.sleep(0.1)
        capture(root, shots / "unified-dashboard-1366.png")
        app.navigate("Investigations")
        await idle(root, app)
        if runtime:
            assert app.current_records
            assert any(x["origin"] == "NATIVE_OS" for x in app.current_records)
            capture(root, shots / "unified-retained-authentication.png")
    finally:
        await close(root, app)
    assert not callbacks
    root = tk.Tk()
    app = Desktop(root, config)
    try:
        await idle(root, app)
        app.navigate("Dashboard")
        await idle(root, app)
        r = app.last_dashboard["research"]
        assert r["demo_state"] == "STOPPED" and r["dns_inference_count"] == 2
        assert r["audit_integrity"] == "VERIFIED" and r["operational_inference"] == "BLOCKED"
        assert all(x["investigation"]["checkpoint_restored"] for x in r["records"])
    finally:
        await close(root, app)
    for p, sha in before.items():
        assert hashlib.sha256(Path(p).read_bytes()).hexdigest() == sha
