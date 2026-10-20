"""Actual four-screen WSLg; preparation only, no privileged backend or model worker."""

import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.gui import PreparationWorker
from tests.ebpf_support import plan
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_prepared_ebpf_four_screens_charts_unknown_no_capture(tmp_path):
    c = EBPFCollector(
        tmp_path / "session", plan(origin="EBPF_TC_NATIVE", clock="KERNEL_MONOTONIC_NS")
    )
    root = tk.Tk()
    worker = PreparationWorker(c)
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"), worker=worker)
    app.terminal_managed = True
    root.title("SOC EBPF PREPARATION ONLY · NO NATIVE HOOK / NO CAPTURE")
    try:
        await idle(root, app)
        assert app.snapshot["ebpf"]["metrics"]["kernel_events"] is None
        for screen in SCREENS:
            app.navigate(screen, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        root.update()
        text = app.system.get("1.0", "end")
        assert (
            "NATIVE_HOOK_PENDING" in text
            and "TC_HOOK_CPU_CUMULATIVE_GENERATION_NOT_ZEEK_HANDLE" in text
        )
        assert "Kernel events / ring loss / queue   UNKNOWN / UNKNOWN / 0" in text
        assert (
            str(app.copy_button["state"]) == "disabled"
            and str(app.start_button["state"]) == "disabled"
        )
        assert not app.command and app.snapshot["research"]["records"] == []
        for width, height in ((1366, 768), (1920, 1080)):
            root.geometry(f"{width}x{height}")
            root.update()
            app.canvas.yview_moveto(1)
            root.update()
            if os.getenv("SOC_EBPF_SCREENSHOTS"):
                capture(
                    root, Path(os.environ["SOC_EBPF_SCREENSHOTS"]) / f"system-prepared-{width}.png"
                )
    finally:
        await close(root, app)
    assert not worker.thread.is_alive() and c.state == "STOPPED"
