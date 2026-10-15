"""Explicit actual WSLg rendering; network data is labeled binary packet Fixture."""

import asyncio
import json
import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configuration
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.state.evidence import utc_now
from tests.gui_visual_checks import screenshot_sizes
from tests.gui_wslg_checks import close, idle
from tests.gui_wslg_checks import (
    release_display_objects_on_creator_thread as release_display_objects_on_creator_thread,
)
from tests.integration.network_monitor.test_pipeline import FixtureCapture, prepare
from tests.unit.network_capture.test_packets import frame


@pytest.mark.asyncio
async def test_actual_gui_graphs_follow_fixture_capture_store_and_gate(tmp_path):
    directory = prepare(tmp_path / "runtime")
    store = RuntimeStore(directory)
    identity = configuration(directory, store)[1]
    capture = FixtureCapture(identity)
    monitor = NetworkMonitor(directory, store, capture=capture)
    with exclusive_runtime_lock(directory / "writer.lock"):
        task = asyncio.create_task(monitor.run())
        root = tk.Tk()
        app = Desktop(
            root,
            GUIConfig(
                data_directory=tmp_path / "gui", runtime_directory=directory, source_label="FIXTURE"
            ),
        )
        try:
            for _ in range(30):
                root.update()
                await asyncio.sleep(0.02)
            await idle(root, app)
            app.refresh()
            await idle(root, app)
            before = app.last_dashboard["network"]["packets_collected"]
            capture.frames.extend([(frame(), utc_now(), "OUTBOUND") for _ in range(4)])
            for _ in range(15):
                root.update()
                await asyncio.sleep(0.02)
            app.refresh()
            await idle(root, app)
            after = app.last_dashboard["network"]
            assert after["packets_collected"] == before + 4
            assert after["inference_count"] == 0
            assert len(app.history.samples) >= 2
            assert app.history.samples[-1].ai_count == 0
            assert app.history.samples[-1].network_rate is not None
            assert "NOT_INFERABLE" in app.network_summary.get()
            assert all(g["inference"] == "BLOCKED" for g in after["gates"].values())
            await screenshot_sizes(root, app, "network-fixture-monitoring")
            if os.getenv("SOC_NETWORK_GUI_RESULT"):
                Path(os.environ["SOC_NETWORK_GUI_RESULT"]).write_text(json.dumps(after, indent=2))
        finally:
            monitor.stopped.set()
            await task
            await close(root, app)
    assert store.verify_audit()
