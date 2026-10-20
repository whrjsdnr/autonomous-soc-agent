"""Existing Desktop with application-session Mock authentication, no Native operation."""

import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS
from soc_agent.security_ai.ebpf_native.gui import PhaseDesktop, PhaseWorker
from tests.ebpf_native_support import authenticated
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_application_auth_state_and_restart_without_repeat_auth(tmp_path):
    c = authenticated(tmp_path)
    # Use the real monotonic clock after the deterministically timed auth fixture.
    c._grant_started = time.monotonic()
    c._last_clock = c._grant_started
    started, cpu = time.monotonic(), time.process_time()
    root = tk.Tk()
    worker = PhaseWorker(c)
    app = PhaseDesktop(root, GUIConfig(data_directory=tmp_path / "gui"), worker=worker)
    root.title("SOC PHASE A FIXTURE · MOCK AUTH ONLY / NO KERNEL HOOK")
    try:
        await idle(root, app)
        if os.getenv("SOC_EBPF_LOADER_GUI_METRICS"):
            rss = (
                int(
                    next(
                        line
                        for line in Path("/proc/self/status").read_text().splitlines()
                        if line.startswith("VmRSS:")
                    ).split()[1]
                )
                * 1024
            )
            Path(os.environ["SOC_EBPF_LOADER_GUI_METRICS"]).write_text(
                json.dumps(
                    dict(
                        scope="ACTUAL_WSLG_PHASE_A_PREAUTHENTICATED_MOCK_NO_NATIVE",
                        startup_seconds=time.monotonic() - started,
                        startup_cpu_seconds=time.process_time() - cpu,
                        idle_rss_bytes=rss,
                        authentication="MOCK_NOT_NATIVE",
                        kernel_capture=False,
                    ),
                    indent=2,
                )
            )
        for page in SCREENS:
            app.navigate(page, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        root.update()
        text = app.system.get("1.0", "end")
        assert "ONCE PER APPLICATION" in text and "MOCK_VERIFIED_NOT_NATIVE" in text
        assert str(app.copy_button["state"]) == "disabled"
        assert str(app.start_button["state"]) == "normal"
        app.start()
        await idle(root, app)
        assert app.snapshot["state"] == "ATTACH_PENDING" and not app.snapshot["collection_live"]
        first = app.snapshot["run"]["capture_session"]
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        app.start()
        await idle(root, app)
        assert app.snapshot["run"]["capture_session"] != first
        assert c.authentication == "MOCK_VERIFIED_NOT_NATIVE"
        assert app.snapshot["native_ai"] == app.snapshot["dns9"] == "BLOCKED"
        for width, height in ((1366, 768), (1920, 1080)):
            root.geometry(f"{width}x{height}")
            root.update()
            app.canvas.yview_moveto(1)
            root.update()
            if os.getenv("SOC_EBPF_LOADER_SCREENSHOTS"):
                capture(
                    root,
                    Path(os.environ["SOC_EBPF_LOADER_SCREENSHOTS"]) / f"system-mock-{width}.png",
                )
    finally:
        await close(root, app)
    assert c.authentication == "REVOKED" and c.attachment is None
    assert not worker.thread.is_alive()
