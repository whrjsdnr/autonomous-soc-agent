"""Actual Tk widgets; preserved reports are verified without new API or Native calls."""

import tkinter as tk

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_ai_page_async_status_and_no_automatic_privilege(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        app.navigate("AI Analysis")
        await idle(root, app)
        assert "NOT_STARTED" in app.analysis_summary.cget("text")
        assert app.worker.backend._owners == {}
        assert app.worker.backend.analysis_service is None
        app.call("analysis_status", callback=app.analysis_updated)
        await idle(root, app)
        assert "IDLE" in app.analysis_summary.cget("text")
        assert "EXTERNAL_GOVERNED_TERMINAL_REQUIRED" in app.analysis_detail.get("1.0", "end")
        assert "INCOMPLETE_TRAINING_EXTRACTION_CONTRACT" in app.analysis_detail.get("1.0", "end")
        assert not app.worker.backend.analysis_service.process
    finally:
        await close(root, app)
    assert app.worker.backend.analysis_service.closed


@pytest.mark.asyncio
async def test_bad_report_does_not_create_a_result(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        app.navigate("AI Analysis")
        await idle(root, app)
        app.call("analysis_attach", str(tmp_path / "missing"), callback=app.analysis_updated)
        await idle(root, app)
        assert "BLOCKED" in app.status.get()
        assert not app.worker.backend.analysis_service.result
    finally:
        await close(root, app)
