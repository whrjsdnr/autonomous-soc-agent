"""WSLg displays the actual offline packet-limit completion; no Native authentication."""

import asyncio
import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.offline import OfflineZeek
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.zeek_producer_support import valid_wire, write_pcap


@pytest.mark.asyncio
async def test_actual_offline_budget_finalization_four_pages(tmp_path, monkeypatch):
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("OFFICIAL_ZEEK_ENVIRONMENT_REQUIRED")

    def forbidden(*args, **kwargs):
        raise AssertionError("NO AUTHENTICATION OR NATIVE CAPTURE IN GUI VERIFICATION")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", forbidden)
    source = tmp_path / "fixture.pcap"
    sha = write_pcap(
        source, [(1800000000000000000 + i * 1000000, valid_wire(flags=16)) for i in range(4096)]
    )
    c = LiveZeekCollector(tmp_path / "offline")
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", collector_type="zeek-live"))
    try:
        await idle(root, app)
        await c.prepare(pcap=source, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        assert c.producer is None and c.state == "STOPPED"
        app.render(c.snapshot())
        for screen in SCREENS:
            app.navigate(screen, refresh=False)
            root.update()
            assert app.snapshot["input_origin"] == "ZEEK_OFFLINE_PCAP"
        app.navigate("System", refresh=False)
        text = app.system.get("1.0", "end")
        assert "PACKET_LIMIT_REACHED" in text and "4096" in text
        assert app.system_details["closed_status"] == "OBSERVED"
        assert app.system_details["cleanup_verified"] is True
        assert app.system_details["finalization_state"] == "DEGRADED"
        assert not app.command and app.copy_button.instate(["disabled"])
        for w, h in ((1920, 1080), (1366, 768)):
            root.geometry(f"{w}x{h}")
            root.update()
            assert root.winfo_width() == w
            if os.getenv("SOC_ZEEK_FINALIZATION_SCREENSHOTS"):
                capture(
                    root,
                    Path(os.environ["SOC_ZEEK_FINALIZATION_SCREENSHOTS"])
                    / f"system-offline-packet-limit-{w}.png",
                )
    finally:
        await c.stop()
        await close(root, app)
    assert not app.worker.thread.is_alive()
