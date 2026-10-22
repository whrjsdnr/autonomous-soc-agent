"""Real signals target ordinary owned test children, never Native collectors."""

import json
import os
import shutil
import signal
import subprocess
import sys

import pytest

from soc_agent.security_ai.collectors import offload_session
from soc_agent.security_ai.ebpf_tc import phase_d
from soc_agent.security_ai.ebpf_tc import supervisor_startup as startup
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession


@pytest.mark.parametrize("guarded", [False, True])
def test_real_sigterm_default_skips_finally_but_boundary_preserves_cleanup(tmp_path, guarded):
    marker = tmp_path / "cleanup"
    code = """
import os,signal,sys
from contextlib import nullcontext
from pathlib import Path
from soc_agent.security_ai.ebpf_tc.supervisor_startup import (
    termination_boundary, SupervisorTermination,
)
try:
    with termination_boundary() if sys.argv[2] == 'True' else nullcontext():
        try:
            print('READY',flush=True)
            signal.pause()
        finally:
            os.kill(os.getpid(),signal.SIGTERM)  # A second signal must not interrupt cleanup.
            Path(sys.argv[1]).write_text('closed')
except SupervisorTermination as exc:
    print(str(exc),flush=True)
    raise SystemExit(128+exc.signum)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(marker), str(guarded)], stdout=subprocess.PIPE, text=True
    )
    try:
        import select

        assert select.select([child.stdout], [], [], 3)[0]
        assert child.stdout.readline().strip() == "READY"
        child.send_signal(signal.SIGTERM)
        output, _ = child.communicate(timeout=3)
        if guarded:
            assert child.returncode == 143 and marker.read_text() == "closed"
            assert "SUPERVISOR_SIGNAL_SIGTERM" in output
        else:
            assert child.returncode == -signal.SIGTERM and not marker.exists()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        child.stdout.close()


def test_signal_handlers_restored_and_cleanup_once():
    previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    closed = []
    with pytest.raises(startup.SupervisorTermination) as caught:
        with startup.termination_boundary():
            try:
                os.kill(os.getpid(), signal.SIGINT)
            finally:
                os.kill(os.getpid(), signal.SIGTERM)
                closed.append("once")
    assert caught.value.signum == signal.SIGINT and closed == ["once"]
    assert all(signal.getsignal(s) == h for s, h in previous.items())


@pytest.fixture(scope="module")
def candidate(tmp_path_factory):
    p = tmp_path_factory.mktemp("supervisor-termination") / "candidate"
    return p, phase_d.prepare(p)


@pytest.mark.parametrize("failure", ["sigterm", "errno", "cleanup"])
def test_real_startup_retains_first_failure_before_cleanup(
    candidate, tmp_path, monkeypatch, failure
):
    source, identity = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    monkeypatch.setattr(offload_session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(SupervisedSession, "authenticate_native", lambda *_: pytest.fail("sudo"))
    if failure == "cleanup":
        original_close = SupervisedSession.close

        def failed_close(self):
            original_close(self)  # Close the actual ordinary fixture FDs before fault injection.
            raise OSError(9, "fixture-only cleanup failure")

        monkeypatch.setattr(SupervisedSession, "close", failed_close)

    def fail(_handoff):
        if failure == "sigterm":
            os.kill(os.getpid(), signal.SIGTERM)
        raise OSError(5, "fixture-only read error, original text must not be stored")

    monkeypatch.setattr(startup, "confirm_scope", fail)
    with pytest.raises(startup.SupervisorTermination if failure == "sigterm" else OSError):
        phase_d.execute(directory, identity["manifest"], identity["image"])
    final = json.loads((directory / "supervised-result.json").read_text())
    first = final["first_failure"]
    assert first["stage"] == "APPROVAL_CONFIRMATION" and first["api"] == "confirm_scope"
    assert first["signal"] == (signal.SIGTERM if failure == "sigterm" else None)
    assert first["errno"] == (None if failure == "sigterm" else 5)
    assert "fixture-only" not in json.dumps(final)
    assert final["tcx"]["source"] != "NATIVE_VERIFIED"
    if failure == "cleanup":
        assert any(
            row["stage"] == "FINAL_NATIVE_CLOSE" and row["errno"] == 9 for row in final["errors"]
        )
