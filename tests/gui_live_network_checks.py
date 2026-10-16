"""Actual WSLg window; prepares only an unprivileged observer. NO privileged helper or capture."""

import asyncio
import socket
import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths


@pytest.mark.asyncio
async def test_actual_live_page_prepare_stop_no_capture_or_model(tmp_path, monkeypatch):
    paths = research_paths()
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", lambda: paths)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    errors = []
    root.report_callback_exception = lambda *args: errors.append(args[0].__name__)
    try:
        await idle(root, app)
        app.navigate("Live Network")
        await idle(root, app)
        view = app.live_view
        view.start_button.invoke()
        view.start_button.invoke()
        await idle(root, app)
        assert view.command.startswith("sudo -n /usr/bin/setpriv")
        assert "--no-new-privs" in view.command
        state = await asyncio.wrap_future(app.worker.submit("live_status"))
        assert not state["collection_live"]
        assert state["state"] == "AUTHENTICATION_REQUIRED"
        assert state["listener_ready"]
        owner = app.worker.backend.live_monitoring
        assert owner.capture.listener_ready() and owner.task and not owner.task.done()
        assert str(view.copy_button.cget("state")) == "normal"
        view.copy_command()
        await idle(root, app)
        assert root.clipboard_get() == view.command
        assert not state["research"]["records"] and not state["research"]["worker_running"]
        for width, height in [(1920, 1080), (1366, 768)]:
            root.geometry(f"{width}x{height}")
            root.update()
            assert root.winfo_ismapped() and view.start_button.winfo_exists()
        app.call("live_stop", callback=view.render)
        await idle(root, app)
        assert "STOPPED" in view.headline.get()
        assert not view.command and str(view.copy_button.cget("state")) == "disabled"
        assert owner.handshake_task.done() and not owner.capture.listener_ready()
        first_session = owner.session
        view.start_button.invoke()
        await idle(root, app)
        assert owner.session.session_id != first_session.session_id
        # Navigation must not destroy the backend-owned listener/task.
        app.navigate("Dashboard")
        await idle(root, app)
        assert owner.capture.listener_ready() and not owner.task.done()
        app.navigate("Live Network")
        await idle(root, app)
        app.live_view.copy_command()
        await idle(root, app)
        assert app.live_view.command and root.clipboard_get() == app.live_view.command
        owner.capture.listener.close()
        await asyncio.wait_for(asyncio.wrap_future(app.worker.submit("live_status")), 2)
        await asyncio.sleep(0.3)
        app.refresh()
        await idle(root, app)
        assert not app.live_view.command
        assert str(app.live_view.copy_button.cget("state")) == "disabled"
        assert "LISTENER_CLOSED" in app.live_view.metrics.get()
        app.live_view.start_button.invoke()
        await idle(root, app)
        assert owner.capture.listener_ready()
        # A real ordinary-user Unix client reaches the GUI-owned accept loop.
        # Its invalid READY must fail closed before any privileged capture exists.
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.connect(owner.session.socket_address)
            client.send(b'{"kind":"READY","session_id":"invalid"}')
        for _ in range(100):
            state = await asyncio.wrap_future(app.worker.submit("live_status"))
            if state["state"] == "ERROR":
                break
            await asyncio.sleep(0.02)
        assert state["state"] == "ERROR" and not state["listener_ready"]
        assert owner.capture.ready is None
        app.refresh()
        await idle(root, app)
        app.live_view.start_button.invoke()
        await idle(root, app)
        assert owner.capture.listener_ready()
        assert not errors
    finally:
        await close(root, app)
    assert owner.task.done() and owner.handshake_task.done()
    assert not owner.capture.listener_ready()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        with pytest.raises(ConnectionRefusedError):
            client.connect(owner.session.socket_address)
