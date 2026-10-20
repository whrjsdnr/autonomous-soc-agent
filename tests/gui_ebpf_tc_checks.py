"""WSLg B-2A compiled identities and B-1 fixture supervisor; no Native operation."""

import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import alive
from soc_agent.security_ai.ebpf_tc.gui import PreparedDesktop, PreparedWorker
from tests.ebpf_tc_support import preparation
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_prepared_native_gate_gui_preserves_charts_and_fixture_shutdown(tmp_path):
    p = preparation(tmp_path / "app")
    p.prepare()
    p.approve(p.plan.approval)
    p.controller.authenticate(FixtureAuthentication())
    start = time.monotonic()
    root = tk.Tk()
    worker = PreparedWorker(p)
    app = PreparedDesktop(root, GUIConfig(data_directory=tmp_path / "gui"), worker=worker)
    root.title("SOC B-2A · NATIVE GATE CLOSED / MOCK AUTH ONLY")
    try:
        await idle(root, app)
        startup = time.monotonic() - start
        for screen in SCREENS:
            app.navigate(screen, refresh=False)
            root.update()
        app.navigate("System", refresh=False)
        root.update()
        text = app.system.get("1.0", "end")
        assert "B-2A NATIVE IMPLEMENTATION" in text and "B2A_CLOSED" in text
        assert p.plan.loader_sha256 in text and p.plan.bootstrap_sha256 in text
        assert not app.snapshot["collection_live"] and app.snapshot["native_ai"] == "BLOCKED"
        app.start()
        await idle(root, app)
        assert app.snapshot["state"] == "ATTACH_PENDING"
        assert app.snapshot["ebpf"]["native_hook"] == "NOT_ATTACHED"
        app.call("collector_stop", callback=app.render)
        await idle(root, app)
        for width, height in ((1366, 768), (1920, 1080)):
            root.geometry(f"{width}x{height}")
            root.update()
        if os.getenv("SOC_EBPF_B2A_GUI_METRICS"):
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
            Path(os.environ["SOC_EBPF_B2A_GUI_METRICS"]).write_text(
                json.dumps(
                    dict(
                        scope="WSLG_WARM_B2A_PREAUTHENTICATED_MOCK_NO_NATIVE",
                        startup_seconds=startup,
                        gui_test_process_rss_bytes=rss,
                        fixture_supervisor=p.controller.broker.metrics(),
                        native_supervisor_rss=None,
                        native_authentication=False,
                    ),
                    indent=2,
                )
            )
    finally:
        await close(root, app)
    assert not worker.thread.is_alive() and not alive(p.controller.broker.identity)
    assert p.controller.application.authentication == "REVOKED"
