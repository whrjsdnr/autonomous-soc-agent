"""Actual Tk/WSLg charts; synthetic observations are explicitly FIXTURE, never Native."""

import os
import time
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa: F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_measured_charts_session_reset_freeze_resize_empty_and_lifecycle(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", source_label="FIXTURE"))
    durations = []
    try:
        await idle(root, app)
        assert tuple(app.nav_buttons) == SCREENS
        assert len(app.dashboard_charts) == 6
        assert all(not c.points.get("raw") for c in app.dashboard_charts)
        assert app.worker.backend._owners == {} and app.worker.backend.model_service is None
        out = os.getenv("SOC_VISUAL_SCREENSHOTS")
        if out:
            for width, height in ((1920, 1080), (1366, 768)):
                root.geometry(f"{width}x{height}")
                root.update()
                capture(root, Path(out) / f"dashboard-initial-{width}.png")
        for i in range(4):
            now = app.last_stamp + 1_000_000_000
            sample = dict(
                session_id="fixture-chart-only",
                input_origin="FIXTURE",
                collection_live=False,
                state="LIVE_COLLECTION",
                observation_started_ns=now,
                network=dict(
                    received_frames=i * 20,
                    sent_packets=i * 10,
                    transport_delivered_packets=i * 8,
                    approved_raw_frames_per_second=256,
                    dns_queries=i * 2,
                    dns_responses=i,
                    capture_drops=0,
                    gap_count=0,
                    runtime_rss_bytes=100 * 1024**2,
                    runtime_cpu_seconds=i * 0.1,
                    queue_backlog=0,
                    transport_queue_depth=0,
                ),
            )
            started = time.monotonic()
            app.render(sample)
            root.update()
            durations.append((time.monotonic() - started) * 1000)
        assert app.visual_history.samples[-1].values["raw"] == 20
        assert app.visual_history.samples[-1].values["normalized"] == 10
        assert app.visual_history.samples[-1].values["delivered"] == 8
        assert app.dashboard_charts[0].points["raw"][-1][1] == 20
        # Integrity-only changes must repaint chart provenance even when values match.
        marker = app.dashboard_charts[0].marker
        app.render(
            {
                **sample,
                "network": {**sample["network"], "integrity_state": "DEGRADED"},
                "observation_started_ns": app.last_stamp + 1,
            }
        )
        assert app.dashboard_charts[0].marker != marker
        frozen = len(app.visual_history.samples)
        app.render(
            {
                **sample,
                "state": "ERROR",
                "last_error": "STREAM_RATE_BUDGET_EXCEEDED",
                "observation_started_ns": app.last_stamp + 1_000_000_000,
            }
        )
        assert len(app.visual_history.samples) == frozen
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for width, height in ((1920, 1080), (1366, 768), (1280, 720)):
                root.geometry(f"{width}x{height}")
                root.update()
                assert app.content.winfo_width() <= width - 180
                for chart in app.content.winfo_children():
                    assert chart.winfo_x() + chart.winfo_width() <= app.content.winfo_width() + 2
                out = os.getenv("SOC_VISUAL_SCREENSHOTS")
                if out and width != 1280:
                    capture(
                        root,
                        Path(out) / f"{page.lower().replace(' ', '-')}-fixture-error-{width}.png",
                    )
        app.render(
            {
                "state": "STOPPED",
                "session_id": "new",
                "input_origin": "NATIVE_AF_PACKET",
                "observation_started_ns": app.last_stamp + 1,
            }
        )
        assert not app.visual_history.samples
        assert len(root.tk.call("after", "info")) == 1
        assert app.worker.backend._owners == {}
        print({"fixture_chart_update_ms": durations, "history_capacity": 60, "screens": 4})
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
