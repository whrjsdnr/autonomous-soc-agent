"""Actual WSLg rendering of retained Native-protocol FIXTURE measurements, no capture."""

import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.integration.zeek_integrity.test_recovery import completed


@pytest.mark.asyncio
async def test_preprocessing_states_windows_and_gates_are_visible(tmp_path, monkeypatch):
    c = await completed(tmp_path / "source", monkeypatch)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui"))
    root.title("SOC Preprocessing — NATIVE-PROTOCOL FIXTURE / NO CAPTURE")
    try:
        await idle(root, app)
        restored = LiveZeekCollector(tmp_path / "source")
        value = await restored.recover()
        value["input_origin"] = "NATIVE_PROTOCOL_FIXTURE_NOT_CAPTURE"
        app.render(value)
        for page in SCREENS:
            app.navigate(page, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        text = app.system.get("1.0", "end")
        assert "ZEEK_GET_NET_STATS_9_0_0" in text and "UNKNOWN" in text
        assert "BLOCKED_CAPTURE_INTEGRITY" in text and "capture not attested" in text
        assert "Normalized packets / active flows" in text
        assert "Timeout-complete / incomplete windows" in text
        assert "IDLE_TIMEOUT" in text and "SHUTDOWN" in text
        assert app.system_details["preprocessing"]["completed_flows"] == 1
        assert app.system_details["preprocessing"]["incomplete_flows"] == 1
        assert app.system_details["preprocessing"]["progress"]["dns"]["records"] == 0
        assert "0 / UNKNOWN" in text
        assert app.system_details["last_verified_process_session"] == str(c.plan.session_id)
        assert not app.snapshot["collection_live"]
        assert app.snapshot["packet_budget"]["used"] == 4
        assert app.snapshot["closed_status"] == "OBSERVED"
        assert app.snapshot["research"]["records"] == []
        for width, height in ((1366, 768), (1920, 1080)):
            root.geometry(f"{width}x{height}")
            root.update()
            assert root.winfo_width() == width
            app.canvas.yview_moveto(1.0)
            root.update()
            if os.getenv("SOC_ZEEK_PREPROCESSING_SCREENSHOTS"):
                capture(
                    root,
                    Path(os.environ["SOC_ZEEK_PREPROCESSING_SCREENSHOTS"])
                    / f"system-fixture-{width}.png",
                )
    finally:
        await c.stop()
        await close(root, app)
    assert not app.worker.thread.is_alive()
