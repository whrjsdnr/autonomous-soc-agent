"""Explicit actual WSLg windows with pinned native research artifacts and offline PCAP."""

import asyncio
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
async def test_real_research_gui_two_models_charts_restart_and_resize(tmp_path):
    shots = Path(os.environ.get("SOC_GUI_SCREENSHOTS", tmp_path / "screens"))
    shots.mkdir(parents=True, exist_ok=True)
    config = GUIConfig(data_directory=tmp_path / "gui")
    root = tk.Tk()
    app = Desktop(root, config)
    try:
        await idle(root, app)
        app.navigate("Network Research")
        await idle(root, app)
        root.geometry("1920x1080")
        root.update()
        before = app.research_view.last_snapshot
        assert before["inference_counts"] == {"quality": 0, "edge": 0}
        capture(root, shots / "research-before-1920.png")
        app.research_view.start_button.invoke()
        await idle(root, app)
        app.research_view.profile.set("both")
        app.research_view.flow.set("1")
        app.research_view.replay_button.invoke()
        await idle(root, app, timeout=90)
        first = app.research_view.last_snapshot
        assert first["inference_counts"] == {"quality": 1, "edge": 1}
        app.research_view.flow.set("3")
        app.research_view.replay_button.invoke()
        await idle(root, app, timeout=90)
        result = app.research_view.last_snapshot
        assert result["inference_counts"] == {"quality": 2, "edge": 2}
        assert result["flow_count"] == 2
        assert all(r["status"] == "COMPLETE" for r in result["records"])
        assert len(app.research_view.trend.rows) == 2
        assert len(app.research_view.trend.find_withtag("replay-point")) == 2
        assert len({r["receipt"]["score"] for r in result["records"]}) > 1
        assert app.research_view.scores.find_withtag("distribution-arc")
        assert "BLOCKED" in app.research_view.headline.get()
        capture(root, shots / "research-after-1920.png")
        root.geometry("1366x768")
        root.update()
        await asyncio.sleep(0.1)
        capture(root, shots / "research-after-1366.png")
        app.research_view.stop_button.invoke()
        await idle(root, app)
        assert app.research_view.last_snapshot["demo_state"] == "STOPPED"
    finally:
        await close(root, app)
    root = tk.Tk()
    app = Desktop(root, config)
    try:
        await idle(root, app)
        app.navigate("Network Research")
        await idle(root, app)
        assert app.research_view.last_snapshot["inference_counts"] == {"quality": 2, "edge": 2}
        assert app.research_view.last_snapshot["demo_state"] == "STOPPED"
        assert app.research_view.last_snapshot["audit_integrity"] == "VERIFIED"
    finally:
        await close(root, app)
