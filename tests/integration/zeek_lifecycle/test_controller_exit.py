import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from soc_agent.security_ai.collectors.live_contract import LivePlan
from soc_agent.security_ai.collectors.live_process import main


def child(tmp_path, *, gui=False):
    log = (tmp_path / "child.log").open("wb")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "tests.zeek_controller_fixture",
            str(tmp_path),
            *(["--gui"] if gui else []),
        ],
        stdout=log,
        stderr=log,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError((tmp_path / "child.log").read_text())
        ready = tmp_path / "fixture-ready.json"
        if ready.exists():
            result = json.loads(ready.read_text())
            assert result["scope"] == "CONTROLLER_LIFECYCLE_FIXTURE_NO_CAPTURE"
            return process, log, Path(result["session"])
        time.sleep(0.05)
    process.kill()
    process.wait(5)
    raise AssertionError("FIXTURE_CONTROLLER_NOT_READY")


@pytest.mark.parametrize("sig,gui", [(signal.SIGTERM, False), (signal.SIGHUP, True)])
def test_terminal_exit_closes_controller_without_capture(tmp_path, sig, gui):
    p, log, session = child(tmp_path, gui=gui)
    try:
        os.kill(p.pid, sig)
        assert p.wait(15) == 0, (tmp_path / "child.log").read_text()
        record = json.loads((session / "stop.request").read_text())
        assert record["reason"] == "CONTROLLER_EXIT"
        assert not any((session / n).exists() for n in ("process.json", "stream.jsonl"))
        plan = LivePlan.model_validate_json((session / "plan.json").read_text())
        with pytest.raises(ValueError, match="CONTROLLER_NOT_RUNNING"):
            main(["--session", str(session), "--approve", plan.identity])
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(5)
        log.close()


def test_controller_crash_rejection_preserves_original_audit(tmp_path):
    p, log, session = child(tmp_path)
    try:
        before = (session / "monitor.sqlite").read_bytes()
        os.kill(p.pid, signal.SIGKILL)
        assert p.wait(5) == -signal.SIGKILL
        assert not (session / "stop.request").exists()
        plan = LivePlan.model_validate_json((session / "plan.json").read_text())
        with pytest.raises(ValueError, match="CONTROLLER_NOT_RUNNING"):
            main(["--session", str(session), "--approve", plan.identity])
        assert (session / "monitor.sqlite").read_bytes() == before
        assert json.loads((session / "stop.request").read_text())["reason"] == "CONTROLLER_EXIT"
        failures = list((session / "launcher-rejections").glob("*.json"))
        assert len(failures) == 1
        assert json.loads(failures[0].read_text())["error"] == "ZEEK_CONTROLLER_NOT_RUNNING"
        assert not (session / "process.json").exists()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait(5)
        log.close()
