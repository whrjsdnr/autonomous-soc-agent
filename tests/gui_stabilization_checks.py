"""Explicit actual WSLg parent-crash/reopen check, with only owned processes signalled."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from soc_agent.gui.backend import Backend, GUIConfig

GUI_CHILD = """
import json, os, sys, time, tkinter as tk
from pathlib import Path
from soc_agent.gui.app import Desktop
from soc_agent.gui.backend import GUIConfig
from soc_agent.security_ai.research import adapter
from tests.research_adapter_support import research_paths
adapter.defaults = research_paths
root = tk.Tk()
app = Desktop(root, GUIConfig(data_directory=Path(sys.argv[1])))
# Use the existing controller on its normal backend event loop; no second Runtime.
starting = app.worker.submit('research_start')
deadline = time.monotonic() + 30
while not starting.done() and time.monotonic() < deadline:
    root.update()
    time.sleep(.01)
starting.result()
replay = app.worker.submit('research_replay', 'edge', 0)
while time.monotonic() < deadline:
    root.update()
    process = app.worker.backend.research_demo.adapter.process
    if process is not None and process.returncode is None:
        # Freeze only the owned model child to make the abrupt-parent race deterministic.
        os.kill(process.pid, __import__('signal').SIGSTOP)
        Path(sys.argv[2]).write_text(json.dumps({'worker':process.pid,'gui':os.getpid(),
                                               'window_mapped':bool(root.winfo_ismapped())}))
        while True:
            root.update()
            time.sleep(.01)
    if replay.done():
        raise RuntimeError('Owned worker exited before fault injection')
    time.sleep(.002)
raise RuntimeError('No owned worker reached dispatch')
"""


def live(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.asyncio
async def test_actual_gui_unexpected_close_worker_cleanup_and_unknown_recovery(tmp_path):
    data, ready = tmp_path / "gui", tmp_path / "ready.json"
    child_log = (tmp_path / "child.log").open("wb")
    process = subprocess.Popen(
        [sys.executable, "-c", GUI_CHILD, str(data), str(ready)],
        stdout=child_log,
        stderr=subprocess.STDOUT,
    )
    worker = None
    try:
        deadline = time.monotonic() + 40
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        assert ready.exists(), (tmp_path / "child.log").read_text()
        state = json.loads(ready.read_text())
        worker = state["worker"]
        assert state["gui"] == process.pid and state["window_mapped"]
        assert live(worker)
        process.kill()  # Only this test's GUI child; external SOC Runtime is never signalled.
        await asyncio.to_thread(process.wait, 3)
        if live(worker):
            os.kill(worker, signal.SIGCONT)  # Covers parent death before Worker bootstrap.
        deadline = time.monotonic() + 5
        while live(worker) and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        assert not live(worker)
        reopened = Backend(GUIConfig(data_directory=data))
        snapshot = await reopened.research_status()
        assert snapshot["demo_state"] == "STOPPED" and not snapshot["worker_running"]
        assert snapshot["audit_integrity"] == "VERIFIED" and snapshot["errors"] == 1
        assert snapshot["model_metrics"]["edge"]["unknown"] == 1
        assert snapshot["inference_counts"] == {"quality": 0, "edge": 0}
        assert snapshot["operational_inference"] == "BLOCKED"
        await reopened.research_start()
        result = await reopened.research_replay("edge", 0)
        assert result["replay_outcomes"] == ["UNKNOWN"]
        assert result["inference_counts"]["edge"] == 0
        await reopened.close()
    finally:
        if process.poll() is None:
            process.kill()
        await asyncio.to_thread(process.wait, 3)
        if worker is not None and live(worker):
            os.kill(worker, signal.SIGKILL)
        child_log.close()
