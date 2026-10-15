"""Owned Linux process fault fixtures; no capture, traffic or security WRITE."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from threading import Event

import pytest

from soc_agent.security_ai.research.service import ResearchDemo

# The real Worker bootstrap/limits run, then a fixture blocks instead of loading a model.
# A separate parent makes abrupt termination safe for the test runner.
BLOCKED_WORKER = """
import os, sys, time
from pathlib import Path
from soc_agent.security_ai.research import worker
ready = Path(sys.argv[1])
def blocked(request, paths):
    ready.write_text(str(os.getpid()))
    time.sleep(30)
worker.run = blocked
sys.argv = sys.argv[2:]
worker.main()
"""
PARENT = """
import os, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2],
    'worker', '--parent-pid', str(os.getpid()), *sys.argv[3:]])
Path(sys.argv[2] + '.pid').write_text(str(child.pid))
time.sleep(30)
"""


def live(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except FileNotFoundError:
        return False


def test_parent_crash_kills_initialized_owned_worker(tmp_path):
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "research_mode": True,
                "profile": "quality",
                "flow_index": 0,
                "invocation_id": "00000000-0000-0000-0000-000000000001",
            }
        )
    )
    ready = tmp_path / "ready"
    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            PARENT,
            BLOCKED_WORKER,
            str(ready),
            "--request",
            str(request),
            "--result",
            str(tmp_path / "result.json"),
            "--ml",
            str(tmp_path),
            "--producer-source",
            str(tmp_path),
        ]
    )
    pid = None
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        pid = int(Path(str(ready) + ".pid").read_text())
        assert ready.exists() and live(pid), "Worker never reached bounded inference fixture"
        parent.kill()
        parent.wait(timeout=3)
        deadline = time.monotonic() + 3
        while live(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not live(pid)
        assert not (tmp_path / "result.json").exists()
    finally:
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=3)
        if pid is None and Path(str(ready) + ".pid").exists():
            pid = int(Path(str(ready) + ".pid").read_text())
        if pid is not None and live(pid):
            os.kill(pid, signal.SIGKILL)


def test_parent_identity_mismatch_refuses_worker_bootstrap(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from soc_agent.security_ai.research.worker import bind_parent; bind_parent(1)",
        ],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0 and b"RESEARCH_PARENT_UNAVAILABLE" in result.stderr


@pytest.mark.asyncio
async def test_stop_during_preflight_cannot_reactivate_demo(tmp_path, monkeypatch):
    demo = ResearchDemo(tmp_path)
    entered, release = Event(), Event()

    def preflight(_="quality"):
        entered.set()
        assert release.wait(5)
        return {"status": "READY"}

    monkeypatch.setattr(demo.adapter, "status", preflight)
    starting = asyncio.create_task(demo.start())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        await demo.stop()
    finally:
        release.set()
    await starting
    assert not demo.started
    assert not demo.directory.exists()


@pytest.mark.asyncio
async def test_duplicate_start_rejected_while_preflight_pending(tmp_path, monkeypatch):
    demo = ResearchDemo(tmp_path)
    entered, release = Event(), Event()

    def preflight(_="quality"):
        entered.set()
        assert release.wait(5)
        return {"status": "BLOCKED"}

    monkeypatch.setattr(demo.adapter, "status", preflight)
    starting = asyncio.create_task(demo.start())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        with pytest.raises(ValueError, match="ALREADY_RUNNING"):
            await demo.start()
    finally:
        release.set()
    assert (await starting)["status"] == "BLOCKED"
    assert not demo.starting and not demo.started
    await demo.stop()
    await demo.stop()
    assert not demo.started


@pytest.mark.parametrize("failure", ["prctl", "parent_race"])
def test_parent_binding_failure_is_closed(monkeypatch, failure):
    from types import SimpleNamespace

    from soc_agent.security_ai.research import worker

    parents = iter([42, 1])
    monkeypatch.setattr(worker.os, "getppid", lambda: next(parents))

    class Prctl:
        def __call__(self, *args):
            assert args == (1, signal.SIGKILL, 0, 0, 0)
            return -1 if failure == "prctl" else 0

    monkeypatch.setattr(worker.ctypes, "CDLL", lambda *a, **k: SimpleNamespace(prctl=Prctl()))
    with pytest.raises(OSError if failure == "prctl" else ValueError):
        worker.bind_parent(42)


def test_worker_address_space_budget_refuses_oversized_mapping():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from soc_agent.security_ai.research.worker import limits; "
            "limits(); import mmap; mmap.mmap(-1, 4 * 1024**3)",
        ],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0
    assert b"Cannot allocate memory" in result.stderr
