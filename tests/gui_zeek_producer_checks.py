"""Actual WSLg + actual offline Zeek + RF/LR, always separate from Native capture."""

import asyncio
import json
import os
import resource
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.collectors.offline import OfflineZeek
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden


@pytest.mark.asyncio
async def test_actual_zeek_network14_models_four_screens_and_shutdown(tmp_path):
    available = int(Path("/proc/meminfo").read_text().split("MemAvailable:")[1].split()[0]) * 1024
    if available < 2 * 1024**3:
        pytest.skip("ACTUAL_MODEL_HEADROOM_REQUIRED")
    try:
        OfflineZeek().environment()
    except (ValueError, OSError):
        pytest.skip("OFFICIAL_ZEEK_IMAGE_NOT_INSTALLED")
    p = tmp_path / "input.pcap"
    sha = golden(p)
    root = tk.Tk()
    app = Desktop(
        root, GUIConfig(data_directory=tmp_path / "gui", collector_type="zeek-network14-offline")
    )
    timings = []
    peak_gui = peak_tree = 0
    started, cpu = time.monotonic(), time.process_time()
    try:
        await idle(root, app)
        assert app.worker.backend._owners == {}

        async def collect():
            b = app.worker.backend
            owner = b._owner("zeek_collector")
            owner.paths = research_paths()
            await b.zeek_start(str(p), sha, True)
            await owner.task
            return await b.production_status()

        future = asyncio.run_coroutine_threadsafe(collect(), app.worker.loop)
        while not future.done():
            from tests.production_slimming_profile import children, memory

            current = memory()["VmRSS"]
            tree = current
            for pid in children():
                try:
                    tree += (
                        int(Path(f"/proc/{pid}/status").read_text().split("VmRSS:")[1].split()[0])
                        * 1024
                    )
                except (OSError, IndexError):
                    continue
            peak_gui, peak_tree = max(peak_gui, current), max(peak_tree, tree)
            root.update()
            await asyncio.sleep(0.01)
        value = future.result()
        app.render(value)
        assert value["collector"]["producer"]["new_inferences"] == 2
        assert value["input_origin"] == "ZEEK_OFFLINE_PCAP" and not value["collection_live"]
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for width, height in ((1920, 1080), (1366, 768)):
                root.geometry(f"{width}x{height}")
                at = time.monotonic()
                root.update()
                timings.append((time.monotonic() - at) * 1000)
                if os.getenv("SOC_ZEEK_PRODUCER_SCREENSHOTS"):
                    capture(
                        root,
                        Path(os.environ["SOC_ZEEK_PRODUCER_SCREENSHOTS"])
                        / (page.lower().replace(" ", "-") + f"-zeek-offline-{width}.png"),
                    )
        app.navigate("Dashboard", refresh=False)
        assert "2 retained research advisories" in app.capture_summary.cget("text")
        assert len(app.dashboard_charts[2].points["quality"]) == 1
        assert len(app.dashboard_charts[2].points["edge"]) == 1
        app.navigate("System", refresh=False)
        assert "VERIFIED_FOR_RECEIPT_WINDOWS" in app.system.get("1.0", "end")
        assert "DNS9 BLOCKED" in app.system.get("1.0", "end")
        assert app.copy_button.instate(["disabled"])
        assert app.worker.backend.model_service is None
        assert set(app.worker.backend._owners) == {"zeek_collector"}
        if os.getenv("SOC_ZEEK_GUI_EVIDENCE"):
            Path(os.environ["SOC_ZEEK_GUI_EVIDENCE"]).write_text(
                json.dumps(
                    dict(
                        scope="ACTUAL_ZEEK_OFFLINE_RF_LR_WSLG_NOT_NATIVE",
                        sampled_peak_gui_rss_bytes=peak_gui,
                        sampled_peak_owned_subtree_rss_bytes=peak_tree,
                        gui_process_peak_rss_bytes=resource.getrusage(
                            resource.RUSAGE_SELF
                        ).ru_maxrss
                        * 1024,
                        elapsed_seconds=time.monotonic() - started,
                        controller_cpu_seconds=time.process_time() - cpu,
                        render_update_ms=timings,
                        collector_metrics=value["collector"]["metrics"],
                        producer=value["collector"]["producer"],
                        inference_latencies_ms=[
                            r["receipt"]["inference_latency_ms"]
                            for r in value["research"]["records"]
                        ],
                        zeek_container_cpu_rss="UNKNOWN_NOT_SAMPLED_BY_HOST_PROCESS_TREE",
                    ),
                    indent=2,
                )
            )
        print({"scope": "ACTUAL_ZEEK_OFFLINE_WSLG_NOT_NATIVE", "render_update_ms": timings})
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
