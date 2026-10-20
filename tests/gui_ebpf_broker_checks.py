"""Actual four-screen WSLg navigation with ordinary-UID Broker fixture only."""

import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS
from soc_agent.security_ai.ebpf_broker.gui import BrokerDesktop, BrokerWorker
from soc_agent.security_ai.ebpf_native.contracts import alive
from tests.ebpf_broker_support import controller
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_broker_gui_ownership_and_graceful_application_shutdown(tmp_path):
    c = controller(tmp_path / "app")
    start, cpu = time.monotonic(), time.process_time()
    root = tk.Tk()
    worker = BrokerWorker(c)
    app = BrokerDesktop(root, GUIConfig(data_directory=tmp_path / "gui"), worker=worker)
    root.title("SOC BROKER B-1 · MOCK AUTH / NO NATIVE HOOK")
    try:
        await idle(root, app)
        startup_seconds = time.monotonic() - start
        for page in SCREENS:
            app.navigate(page, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        root.update()
        text = app.system.get("1.0", "end")
        assert "BROKER PHASE B-1" in text and "MOCK_VERIFIED_NOT_NATIVE" in text
        assert str(app.copy_button["state"]) == "disabled"
        assert str(app.start_button["state"]) == "normal"
        app.start()
        await idle(root, app)
        assert app.snapshot["state"] == "ATTACH_PENDING"
        assert "TC_REGISTRY_FIXTURE_NOT_KERNEL" in app.system.get("1.0", "end")
        assert not app.snapshot["collection_live"]
        first = c.run.capture_session
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        app.start()
        await idle(root, app)
        assert c.run.capture_session != first
        for width, height in ((1366, 768), (1920, 1080)):
            root.geometry(f"{width}x{height}")
            root.update()
        if os.getenv("SOC_EBPF_BROKER_GUI_METRICS"):
            rss = (
                int(
                    next(
                        v.split()[1]
                        for v in Path("/proc/self/status").read_text().splitlines()
                        if v.startswith("VmRSS:")
                    )
                )
                * 1024
            )
            Path(os.environ["SOC_EBPF_BROKER_GUI_METRICS"]).write_text(
                json.dumps(
                    dict(
                        scope="WARM_WSLG_BROKER_PREAUTHENTICATED_FIXTURE_NO_NATIVE",
                        startup_seconds=startup_seconds,
                        elapsed_navigation_and_start_stop_seconds=time.monotonic() - start,
                        cpu_seconds=time.process_time() - cpu,
                        rss_bytes=rss,
                        broker=c.broker.metrics(),
                        kernel_capture=False,
                    ),
                    indent=2,
                )
            )
    finally:
        await close(root, app)
    assert not worker.thread.is_alive() and not alive(c.broker.identity)
    assert c.application.authentication == "REVOKED" and c.cleanup == "FIXTURE_VERIFIED"
