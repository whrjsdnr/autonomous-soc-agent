"""Real Tk + independent ordinary service lifecycle; no Native or API calls."""

import asyncio
import hashlib
import json
import tkinter as tk

import pytest

from soc_agent.continuous.cli import main, start, status
from soc_agent.continuous.store import Store
from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.production import Desktop
from tests.gui_wslg_checks import (  # noqa:F401
    close,
    idle,
    release_display_objects_on_creator_thread,
)


@pytest.mark.asyncio
async def test_gui_detach_reconnect_and_owned_service_stop(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        json.dumps(
            dict(
                sequence=1,
                id="6a3fced6-dd7f-480e-9cb5-2f16b6b5a0ed",
                kind="excluded",
                affects_integrity=False,
            )
        )
        + "\n"
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            dict(
                source="JSONL_REPLAY",
                input_file=str(source),
                input_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                heartbeat_seconds=0.1,
            )
        )
    )
    directory = tmp_path / "service"
    assert main(["init", str(directory), "--config", str(config)]) == 0
    launched = await asyncio.to_thread(start, directory)
    assert launched["status"] == "SERVICE_HEARTBEAT_VERIFIED"
    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=tmp_path / "gui1", continuous_directory=directory))
    try:
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        assert "JSONL_REPLAY" in app.continuous_summary.cget("text")
        with pytest.raises(BlockingIOError):
            await asyncio.to_thread(start, directory)
        await close(root, app)
        assert status(directory)["state"] == "RUNNING"
        root = tk.Tk()
        app = Desktop(
            root, GUIConfig(data_directory=tmp_path / "gui2", continuous_directory=directory)
        )
        await idle(root, app)
        app.navigate("Continuous")
        await idle(root, app)
        assert "Native live: False" in app.continuous_summary.cget("text")
    finally:
        await close(root, app)
        Store(directory).control(stop=True)
        for _ in range(100):
            if status(directory).get("state") == "STOPPED":
                break
            await asyncio.sleep(0.1)
    assert status(directory)["cleanup"] == "VERIFIED"
