"""WSLg preparation UX only. No authentication, no Native capture, no invented events."""

import json
import os
import resource
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_zeek_live_prepare_four_pages_no_capture(tmp_path, monkeypatch):
    def no_auth(*args, **kwargs):
        raise AssertionError("GUI MUST NOT AUTHENTICATE")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", no_auth)
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    started = time.monotonic()
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    timings = []
    try:
        await idle(root, app)
        startup = time.monotonic() - started
        assert app.worker.backend._owners == {}
        app.start()
        await idle(root, app)
        value = app.snapshot
        assert value["state"] == "AUTHENTICATION_REQUIRED"
        assert not value["collection_live"] and not value["listener_ready"]
        assert value["collector"]["type"] == "zeek-live"
        assert app.command and "--approve" in app.command
        assert app.worker.backend.model_service is None
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for width, height in ((1920, 1080), (1366, 768)):
                root.geometry(f"{width}x{height}")
                before = time.monotonic()
                root.update()
                timings.append((time.monotonic() - before) * 1000)
                assert root.winfo_width() == width
                if os.getenv("SOC_ZEEK_LIVE_SCREENSHOTS"):
                    capture(
                        root,
                        Path(os.environ["SOC_ZEEK_LIVE_SCREENSHOTS"])
                        / f"{page.lower().replace(' ', '-')}-not-started-{width}.png",
                    )
        app.navigate("System", refresh=False)
        assert not app.start_button.instate(["!disabled"])
        assert app.copy_button.instate(["!disabled"])
        assert "UNVERIFIED" in app.system.get("1.0", "end")
        app.copy_command()
        await idle(root, app)
        assert "--approve" in root.clipboard_get()
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        assert app.snapshot["state"] == "STOPPED" and not app.command
        assert app.copy_button.instate(["disabled"])
        if os.getenv("SOC_ZEEK_LIVE_GUI_EVIDENCE"):
            Path(os.environ["SOC_ZEEK_LIVE_GUI_EVIDENCE"]).write_text(
                json.dumps(
                    dict(
                        scope="ACTUAL_WSLG_GUI_MOCK_ENVIRONMENT_NO_AUTHENTICATION_NO_CAPTURE",
                        startup_seconds=startup,
                        render_ms=timings,
                        process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        * 1024,
                        current_rss_bytes=int(
                            Path("/proc/self/status").read_text().split("VmRSS:")[1].split()[0]
                        )
                        * 1024,
                        backend_owner_count=len(app.worker.backend._owners),
                        model_loader=app.worker.backend.model_service is not None,
                        authentication_calls=0,
                        native_capture=False,
                    ),
                    indent=2,
                )
            )
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
