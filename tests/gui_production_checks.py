"""Actual WSLg operator navigation; authentication/capture are mocked, never invoked."""

import asyncio
import json
import tkinter as tk
from unittest.mock import AsyncMock

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_four_pages_no_research_initialization_and_restart(tmp_path):
    for _ in range(2):
        root = tk.Tk()
        app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
        try:
            await idle(root, app)
            assert list(app.nav_buttons) == list(SCREENS)
            assert app.worker.backend._owners == {}
            assert app.worker.backend.model_service is None
            for name in SCREENS:
                app.navigate(name)
                await idle(root, app)
                assert app.page == name
                assert app.worker.backend._owners == {}
                assert len(root.tk.call("after", "info")) == 1
            for width, height in ((1920, 1080), (1366, 768)):
                root.geometry(f"{width}x{height}")
                root.update()
                assert app.content.winfo_width() <= width
                assert (
                    app.copy_button.winfo_rootx() + app.copy_button.winfo_width()
                    <= root.winfo_rootx() + width
                )
            assert app.copy_button.instate(["disabled"])
            assert "NOT_PREPARED" in app.system.get("1.0", "end")
        finally:
            await close(root, app)
        assert not app.worker.thread.is_alive()
        assert app.worker.loop.is_closed()


@pytest.mark.asyncio
async def test_ready_error_stale_response_and_no_automatic_authentication(tmp_path, monkeypatch):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        app.navigate("System")
        await idle(root, app)
        calls = AsyncMock()
        monkeypatch.setattr(app.worker.backend, "total_authenticate", calls)
        stamp = app.last_stamp + 10
        ready = {
            "state": "AUTHENTICATION_REQUIRED",
            "listener_ready": True,
            "session_id": "fixture",
            "helper_sha256": "a" * 64,
            "command": "MOCK_ONLY_NEVER_EXECUTED",
            "observation_started_ns": stamp,
        }
        app.prepared(ready)
        assert app.command and app.copy_button.instate(["!disabled"])
        assert calls.await_count == 0
        app.render(
            {
                "state": "ERROR",
                "last_error": "STREAM_ARCHIVAL_REQUIRED",
                "listener_ready": False,
                "observation_started_ns": stamp + 1,
            }
        )
        app.prepared(ready)
        assert not app.command and app.copy_button.instate(["disabled"])
        assert "STREAM_ARCHIVAL_REQUIRED" in app.status.get()
        assert calls.await_count == 0
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_records_search_details_and_export_are_read_only(tmp_path, monkeypatch):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        row = {
            "receipt": {
                "profile": "quality",
                "score": 0.95,
                "origin": "FIXTURE",
                "artifact_digest": "a" * 64,
            },
            "investigation": {"status": "ASSESSED_READ_ONLY", "assessment": "RESEARCH_ONLY"},
            "advisory_current": "WITHDRAWN_RESEARCH_ONLY",
        }
        app.render(
            {
                **app.snapshot,
                "research": {"records": [row]},
                "observation_started_ns": app.last_stamp + 1,
            }
        )
        app.navigate("Security Events", refresh=False)
        assert len(app.tree.get_children()) == 1
        app.tree.selection_set("0")
        app.select()
        assert "WITHDRAWN_RESEARCH_ONLY" in app.detail.get("1.0", "end")
        app.render(
            {
                **app.snapshot,
                "gui_resources": {"cpu_seconds": 99},
                "observation_started_ns": app.last_stamp + 1,
            }
        )
        assert "WITHDRAWN_RESEARCH_ONLY" in app.detail.get("1.0", "end")
        app.search.set("NATIVE_AF_PACKET")
        app._render_current()
        assert not app.tree.get_children()
        app.navigate("Investigation", refresh=False)
        assert len(app.tree.get_children()) == 1
        result = tmp_path / "report.json"
        monkeypatch.setattr(
            "soc_agent.gui.production.filedialog.asksaveasfilename", lambda **_: str(result)
        )
        export = AsyncMock(return_value={"status": "EXPORTED_LOCAL_ONLY"})
        monkeypatch.setattr(app.worker.backend, "total_export", export)
        app.export("json")
        await idle(root, app)
        export.assert_awaited_once_with(str(result), "json")
        assert "WRITE" not in json.dumps(list(app.nav_buttons))
    finally:
        await close(root, app)


@pytest.mark.asyncio
async def test_navigation_during_pending_status_cannot_restore_old_widgets(tmp_path, monkeypatch):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    try:
        await idle(root, app)
        original = app.worker.backend.production_status

        async def slow():
            await asyncio.sleep(0.1)
            return await original()

        monkeypatch.setattr(app.worker.backend, "production_status", slow)
        app.refresh()
        app.navigate("Investigation", refresh=False)
        await idle(root, app)
        assert app.page == "Investigation" and app.tree.winfo_exists()
        assert not app.busy
    finally:
        await close(root, app)
