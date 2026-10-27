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
from soc_agent.security_ai.ebpf_tc.termination import (
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


@pytest.mark.parametrize(
    "code,close_failure",
    [
        ("EBPF_REORDER_LATE_CAPTURE_GAP", False),
        ("EBPF_CHECKPOINT_SIZE", False),
        ("EBPF_CHECKPOINT_FLUSH_UNVERIFIED", True),
    ],
)
def test_processing_failure_is_first_failure_and_does_not_require_control_revocation(
    candidate, tmp_path, monkeypatch, code, close_failure
):
    source, identity = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    monkeypatch.setattr(offload_session.os, "isatty", lambda fd: True)
    # Unit-level failure injection begins after environment preflight. The real
    # dependency/hash gate is tested separately and must not be bypassed in use.
    monkeypatch.setattr(offload_session, "preflight", lambda *a, **kw: None)
    # Phase D must never enter the failed legacy reader or Operator API path.
    # Authentication and DNS capture are explicitly mocked; no Root or traffic.
    from soc_agent.linux_runtime.operator import OperatorServer

    calls = []

    async def forbidden_start(*_args, **_kwargs):
        pytest.fail("Phase D entered a legacy reader or Operator START path")

    original_stop = startup.LiveZeekCollector.stop

    async def adapter_stop(self, *args, **kwargs):
        calls.append("shared_adapter_stop")
        return await original_stop(self, *args, **kwargs)

    monkeypatch.setattr(startup.LiveZeekCollector, "start", forbidden_start)
    monkeypatch.setattr(OperatorServer, "start", forbidden_start)
    monkeypatch.setattr(startup.LiveZeekCollector, "stop", adapter_stop)
    monkeypatch.setattr(startup, "confirm_scope", lambda *_: True)
    monkeypatch.setattr(SupervisedSession, "authenticate_native", lambda *_: None)
    monkeypatch.setattr(SupervisedSession, "observe", lambda self: self.snapshot())

    def command(self, value):
        if value.command == "ATTACH":
            self.data.error = code

    monkeypatch.setattr(SupervisedSession, "command", command)
    if close_failure:
        original_close = SupervisedSession.close

        def failed_close(self):
            original_close(self)
            raise OSError(5, "injected cleanup error")

        monkeypatch.setattr(SupervisedSession, "close", failed_close)

    def dns_execute(*_args, **_kwargs):
        calls.append("phase_d_dns")
        return {"state": "CLOSED"}

    monkeypatch.setattr(offload_session, "execute", dns_execute)
    with pytest.raises(ValueError, match=code):
        phase_d.execute(directory, identity["manifest"], identity["image"])
    result = json.loads((directory / "supervised-result.json").read_text())
    assert result["first_failure"]["original_code"] == code
    assert result["first_failure"]["stage"] == "TCX_DATA_PROCESSING"
    assert result["first_failure"]["errno"] is None
    assert not result["tcx"]["control_failures"]
    assert calls == ["phase_d_dns", "shared_adapter_stop"]
    if close_failure:
        assert any(
            row["stage"] == "FINAL_NATIVE_CLOSE" and row["errno"] == 5 for row in result["errors"]
        )


@pytest.fixture(scope="module")
def candidate(tmp_path_factory):
    from soc_agent.security_ai.ebpf_tc import unified_image

    p = tmp_path_factory.mktemp("supervisor-termination") / "candidate"
    # This is a first-install, pre-authentication failure fixture. It must not
    # depend on an operator's actual installed version or OS dependency upgrades.
    # Production qualification is untouched; no old runtime is declared valid.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(unified_image, "INSTALL", p.parent / "absent-fixture-installation")
        return p, phase_d.prepare(p)


@pytest.mark.parametrize("failure", ["sigterm", "errno", "cleanup"])
def test_real_startup_retains_first_failure_before_cleanup(
    candidate, tmp_path, monkeypatch, failure
):
    source, identity = candidate
    directory = tmp_path / "candidate"
    shutil.copytree(source, directory)
    monkeypatch.setattr(offload_session.os, "isatty", lambda fd: True)
    monkeypatch.setattr(offload_session, "preflight", lambda *a, **kw: None)
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


@pytest.mark.parametrize("primary", [None, dict(stage="PROCESSING", original_code="FIRST_ERROR")])
def test_returned_cleanup_failure_is_top_level_without_replacing_primary(primary):
    snapshot = dict(last_error="SUPERVISOR_CLEANUP_UNVERIFIED", cleanup_status="CLEANUP_UNVERIFIED")
    result = startup.final_result(snapshot, dict(state="CLOSED"), [], primary)
    detail = result["errors"][0]
    assert detail["original_code"] == "SUPERVISOR_CLEANUP_UNVERIFIED"
    assert detail["errno"] is None
    assert detail["stage"] == "FINAL_NATIVE_STATE"
    assert result["first_failure"] == (primary or detail)
    assert result["tcx"] == snapshot and result["zeek"]["state"] == "CLOSED"


def test_successful_final_snapshot_does_not_manufacture_failure():
    result = startup.final_result(dict(last_error=None), {}, [], None)
    assert result["first_failure"] is None and not result["errors"]


def test_supervisor_uses_exact_signal_only_boundary():
    from soc_agent.security_ai.ebpf_tc.termination import (
        SupervisorTermination,
        termination_boundary,
    )

    assert startup.SupervisorTermination is SupervisorTermination
    assert startup.termination_boundary is termination_boundary
