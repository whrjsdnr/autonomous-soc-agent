"""Actual WSLg, explicitly SYNTHETIC JSON source; no Zeek/native process or model."""

import asyncio
import os
import tkinter as tk
from pathlib import Path

import pytest

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import SCREENS, Desktop
from soc_agent.security_ai.collectors.zeek import FixtureCollector
from tests.gui_screen_capture import capture
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)
from tests.zeek_collector_support import row


@pytest.mark.asyncio
async def test_four_screens_collector_provenance_blocked_model_and_export(tmp_path):
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", collector_type="zeek-offline"))
    try:
        await idle(root, app)
        assert app.worker.backend._owners == {}

        async def collect():
            b = app.worker.backend
            c = FixtureCollector(b.directory)
            b._owners["zeek_collector"] = c
            b.collector_selection = "zeek-offline"
            await c.prepare_logs({"conn.log": row(), "dns.log": row("dns")})
            await c.start()
            await c.task
            return await b.production_status()

        future = asyncio.run_coroutine_threadsafe(collect(), app.worker.loop)
        while not future.done():
            root.update()
            await asyncio.sleep(0.01)
        snap = future.result()
        app.render(snap)
        assert snap["collector"]["metrics"]["network_events"] == 1
        assert not snap["collection_live"] and snap["research"]["records"] == []
        for page in SCREENS:
            app.navigate(page, refresh=False)
            for width, height in [(1920, 1080), (1366, 768)]:
                root.geometry(f"{width}x{height}")
                root.update()
                assert app.content.winfo_width() <= width - 180
                out = os.getenv("SOC_ZEEK_SCREENSHOTS")
                if out:
                    capture(
                        root,
                        Path(out) / (page.lower().replace(" ", "-") + f"-synthetic-{width}.png"),
                    )
        app.navigate("Dashboard", refresh=False)
        assert "0 retained research advisories" in app.capture_summary.cget("text")
        app.navigate("Security Events", refresh=False)
        assert len(app.tree.get_children()) == 2
        app.tree.selection_set("0")
        app.select()
        detail = app.detail.get("1.0", "end")
        assert "SYNTHETIC_ZEEK_JSON" in detail and "DIAGNOSTIC ONLY" in detail
        app.navigate("System", refresh=False)
        assert app.copy_button.instate(["disabled"])
        assert "BLOCKED: Network14 / DNS9" in app.system.get("1.0", "end")
        assert len(root.tk.call("after", "info")) == 1
        assert app.worker.backend.model_service is None

        async def export():
            b = app.worker.backend
            await b.total_export(str(b.directory / "zeek.json"))
            await b.total_export(str(b.directory / "zeek.md"), "markdown")
            assert "total_monitoring" not in b._owners

        f = asyncio.run_coroutine_threadsafe(export(), app.worker.loop)
        while not f.done():
            root.update()
            await asyncio.sleep(0.01)
        f.result()
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()


@pytest.mark.asyncio
async def test_actual_zeek_offline_pcap_in_existing_gui(tmp_path):
    from soc_agent.security_ai.collectors.offline import OfflineZeek
    from tests.zeek_collector_support import pcap_fixture

    try:
        OfflineZeek().environment()
    except (ValueError, OSError):
        pytest.skip("OFFICIAL_ZEEK_IMAGE_NOT_INSTALLED")
    pcap = tmp_path / "golden.pcap"
    sha = pcap_fixture(pcap)
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui", collector_type="zeek-offline"))
    try:
        await idle(root, app)

        async def collect():
            b = app.worker.backend
            await b.zeek_start(str(pcap), sha)
            await b._owners["zeek_collector"].task
            return await b.production_status()

        f = asyncio.run_coroutine_threadsafe(collect(), app.worker.loop)
        while not f.done():
            root.update()
            await asyncio.sleep(0.01)
        snapshot = f.result()
        assert snapshot["input_origin"] == "ZEEK_OFFLINE_PCAP"
        assert snapshot["collector"]["metrics"]["network_events"] == 2
        assert snapshot["collector"]["metrics"]["dns_events"] == 1
        assert snapshot["runtime_audit_integrity"] == "VERIFIED"
        assert snapshot["research"]["records"] == [] and not snapshot["collection_live"]
        app.render(snapshot)
        for page in ("Dashboard", "System"):
            app.navigate(page, refresh=False)
            for width, height in ((1920, 1080), (1366, 768)):
                root.geometry(f"{width}x{height}")
                root.update()
                if os.getenv("SOC_ZEEK_SCREENSHOTS"):
                    capture(
                        root,
                        Path(os.environ["SOC_ZEEK_SCREENSHOTS"])
                        / f"{page.lower()}-actual-zeek-offline-{width}.png",
                    )
        assert app.worker.backend.model_service is None
        assert set(app.worker.backend._owners) == {"zeek_collector"}
    finally:
        await close(root, app)
    assert not app.worker.thread.is_alive()
