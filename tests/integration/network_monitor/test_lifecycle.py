"""Runtime/GUI ownership and optional capture failures, no native capture authority."""

import asyncio
import json
import os
import subprocess
import sys
from uuid import uuid4

import pytest
from tests.integration.network_monitor.test_pipeline import prepare

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.charts import MetricHistory
from soc_agent.linux_runtime.__main__ import status
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import configure, network_status
from soc_agent.linux_runtime.service import LinuxMonitor, initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig


@pytest.mark.asyncio
async def test_runtime_optional_capture_permission_failure_is_not_ready(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    initialize(
        root,
        RuntimeConfig(
            incident_id=uuid4(),
            repeated_failures=5,
            multiple_accounts=3,
            poll_seconds=0.2,
            assessment_mode="READ_ONLY",
        ),
    )
    configure(root, CaptureConfig(interface="lo"))
    monkeypatch.setattr(LinuxAuthenticationCollector, "poll", lambda self, cursor, limit: [])
    runtime = LinuxMonitor(root)
    await runtime.run(duration_seconds=0.4)
    state = RuntimeStore(root).state()
    assert state["network"]["state"] == "DEGRADED"
    assert state["network"]["last_error"] == "PERMISSION_DENIED"
    assert state["network"]["capture_drops"] is None
    assert status(root)["readiness"] == "NOT_READY"
    assert RuntimeStore(root).verify_audit()


def test_stale_capture_state_does_not_imply_live_ready(tmp_path):
    from datetime import timedelta

    from soc_agent.state.evidence import utc_now

    root = prepare(tmp_path / "runtime")
    store = RuntimeStore(root)
    store.update(
        network={
            "state": "RUNNING",
            "readiness": "COLLECTING_DIAGNOSTIC_ONLY",
            "measured_at": (utc_now() - timedelta(seconds=30)).isoformat(),
            "packets_per_second": 99,
        }
    )
    state = network_status(root, store)
    assert state["state"] == "UNKNOWN" and state["readiness"] == "NOT_READY"
    assert state["packets_per_second"] is None


def test_live_charts_use_values_or_unknown_and_do_not_mix_fixture_counts():
    history = MetricHistory()
    history.observe(
        {"network": {"packets_per_second": 4.5, "dns_queries_per_minute": 2, "inference_count": 0}},
        now=1,
    )
    history.observe(
        {"network": {"packets_per_second": None, "dns_queries_per_minute": float("nan")}}, now=2
    )
    first, second = history.samples
    assert first.network_rate == 4.5 and first.dns_rate == 2 and first.ai_count == 0
    assert second.network_rate is None and second.dns_rate is None and second.ai_count is None


@pytest.mark.asyncio
async def test_gui_close_detaches_explicit_runtime_and_manual_stop_still_works(tmp_path):
    root = tmp_path / "runtime"
    initialize(
        root,
        RuntimeConfig(
            incident_id=uuid4(),
            repeated_failures=5,
            multiple_accounts=3,
            poll_seconds=0.2,
            assessment_mode="READ_ONLY",
        ),
    )
    gui = Backend(GUIConfig(data_directory=tmp_path / "gui", runtime_directory=root))
    try:
        assert (await gui.start())["status"] == "START_REQUESTED"
        end = asyncio.get_running_loop().time() + 15
        while (
            RuntimeStore(root).state()["state"] != "RUNNING"
            and asyncio.get_running_loop().time() < end
        ):
            await asyncio.sleep(0.1)
        closed = await gui.close()
        assert closed["runtime_continues"] and gui.child.returncode is None
        assert RuntimeStore(root).state()["state"] == "RUNNING"
    finally:
        await gui.stop()
    assert gui.child.returncode == 0


def test_gui_process_exit_does_not_kill_independent_runtime(tmp_path):
    root = tmp_path / "runtime"
    initialize(
        root,
        RuntimeConfig(
            incident_id=uuid4(),
            repeated_failures=5,
            multiple_accounts=3,
            poll_seconds=0.2,
            assessment_mode="READ_ONLY",
        ),
    )
    # Fixed Python script, paths passed as data, no shell/model commands.
    script = """import asyncio,sys,json
from pathlib import Path
from soc_agent.gui.backend import Backend,GUIConfig
async def main():
 b=Backend(GUIConfig(data_directory=Path(sys.argv[1]),runtime_directory=Path(sys.argv[2])))
 await b.start()
 end=asyncio.get_running_loop().time()+15
 from soc_agent.linux_runtime.store import RuntimeStore
 while RuntimeStore(Path(sys.argv[2])).state()["state"]!="RUNNING":
  if b.child.returncode is not None or asyncio.get_running_loop().time()>end:
   raise RuntimeError("OWNED_RUNTIME_START_TIMEOUT")
  await asyncio.sleep(.1)
 print(json.dumps({"pid":b.child.pid,"close":await b.close()}))
asyncio.run(main())
"""
    child = None
    try:
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / "gui"), str(root)],
            capture_output=True,
            timeout=20,
            check=True,
        )
        value = json.loads(result.stdout)
        child = value["pid"]
        assert value["close"]["runtime_continues"]
        os.kill(child, 0)  # Probe existence only, no signal is delivered.
        assert RuntimeStore(root).state()["state"] == "RUNNING"
    finally:
        if child is not None:
            subprocess.run(
                [sys.executable, "-m", "soc_agent.linux_runtime", "--directory", str(root), "stop"],
                capture_output=True,
                timeout=10,
                check=True,
            )
