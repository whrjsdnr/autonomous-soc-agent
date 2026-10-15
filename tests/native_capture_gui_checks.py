"""Explicit WSLg check of a real permission-denied collector, never a live success."""

import tkinter as tk

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.operational.network_capture.permissions import privileges
from tests.gui_visual_checks import screenshot_sizes
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_actual_denied_capture_is_visible_and_not_ready(tmp_path):
    if privileges()["CapEff"] != 0:
        pytest.skip("requires the unprivileged WSL environment")
    from uuid import uuid4

    directory = tmp_path / "runtime"
    initialize(
        directory, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
    )
    configure(directory, CaptureConfig(interface="lo"))
    monitor = NetworkMonitor(directory, RuntimeStore(directory))
    await monitor.run()
    assert monitor.metrics["last_error"] == "PERMISSION_DENIED"
    root = tk.Tk()
    app = Desktop(
        root,
        GUIConfig(
            data_directory=tmp_path / "gui", runtime_directory=directory, source_label="LIVE_WSL"
        ),
    )
    try:
        await idle(root, app)
        app.refresh()
        await idle(root, app)
        assert "PERMISSION_DENIED" in app.network_summary.get()
        assert app.last_dashboard["network"]["capture_drops"] is None
        assert app.last_dashboard["network"]["readiness"] == "NOT_READY"
        assert all(
            g["inference"] == "BLOCKED" for g in app.last_dashboard["network"]["gates"].values()
        )
        await screenshot_sizes(root, app, "native-capture-permission-denied")
    finally:
        await close(root, app)
