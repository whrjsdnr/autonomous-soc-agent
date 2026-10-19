"""Actual WSLg + actual RF/LR, synthetic source only. No privileged helper is invoked."""

import asyncio
import json
import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from soc_agent.security_ai.operational.network_capture.direction_policy import DirectionPolicy
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.production_slimming_profile import children, memory
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import idle_source


@pytest.mark.asyncio
async def test_actual_models_in_operator_dashboard_investigation_and_shutdown(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    if available < 2 * 1024**3:
        pytest.skip("REAL_MODEL_VALIDATION_BLOCKED_MEMORY_HEADROOM")
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", source_label="FIXTURE"))
    try:
        await idle(root, app)

        async def run():
            owner = app.worker.backend.total_monitoring
            owner.paths = research_paths()
            await owner.start_fixture(idle_source(owner), policy=DirectionPolicy())
            await asyncio.wait_for(owner.task, 40)
            return await app.worker.backend.production_status()

        peak_gui_rss = peak_subtree_rss = max_children = 0
        started, cpu = time.monotonic(), time.process_time()
        future = asyncio.run_coroutine_threadsafe(run(), app.worker.loop)
        deadline = time.monotonic() + 50
        while not future.done() and time.monotonic() < deadline:
            rss = memory()["VmRSS"]
            owned = children()
            subtree = rss
            for pid in owned:
                try:
                    subtree += (
                        int(Path(f"/proc/{pid}/status").read_text().split("VmRSS:")[1].split()[0])
                        * 1024
                    )
                except (OSError, IndexError, ValueError):
                    continue
            peak_gui_rss = max(peak_gui_rss, rss)
            peak_subtree_rss = max(peak_subtree_rss, subtree)
            max_children = max(max_children, len(owned))
            root.update()
            await asyncio.sleep(0.02)
        snapshot = future.result(1)
        assert snapshot["network"]["inference_count"] == 2
        assert snapshot["network"]["finalization"] == "VERIFIED"
        assert snapshot["input_origin"] == "FIXTURE" and not snapshot["collection_live"]
        assert snapshot["network"]["queue_backlog"] == 0
        assert snapshot["runtime_audit_integrity"] == "VERIFIED"
        render_started = time.monotonic()
        app.render(snapshot)
        render_seconds = time.monotonic() - render_started
        output = os.getenv("SOC_DIRECTION_GUI_EVIDENCE")
        if output:
            Path(output).write_text(
                json.dumps(
                    {
                        "scope": "ACTUAL_WSLG_RF_LR_SYNTHETIC_FIXTURE_NOT_NATIVE",
                        "elapsed_seconds": time.monotonic() - started,
                        "controller_cpu_seconds": time.process_time() - cpu,
                        "render_seconds": render_seconds,
                        "sampled_peak_gui_rss_bytes": peak_gui_rss,
                        "sampled_peak_subtree_rss_bytes": peak_subtree_rss,
                        "maximum_owned_child_processes": max_children,
                        "network": snapshot["network"],
                        "records": snapshot["research"]["records"],
                        "audit_integrity": snapshot["runtime_audit_integrity"],
                    },
                    indent=2,
                )
            )
        directory = os.getenv("SOC_GUI_SCREENSHOTS")
        if directory:
            root.geometry("1366x768")
            root.update()
            capture(root, Path(directory) / "dashboard-actual-model-fixture-1366.png")
        app.navigate("Investigation", refresh=False)
        assert len(app.tree.get_children()) == 2
        app.tree.selection_set("0")
        app.select()
        assert "FIXTURE" in app.detail.get("1.0", "end")
        assert "ASSESSED_READ_ONLY" in app.detail.get("1.0", "end")
        if directory:
            root.update()
            capture(root, Path(directory) / "investigation-actual-model-fixture-1366.png")
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
    assert (
        app.worker.backend.total_monitoring.demo.adapter.process is None
        or app.worker.backend.total_monitoring.demo.adapter.process.returncode is not None
    )
