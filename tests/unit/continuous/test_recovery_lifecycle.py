"""Stored/synthetic evidence only: no Root, Kernel load, TCP traffic or model invocation."""

import asyncio
import ctypes
import errno
from unittest.mock import Mock

import pytest
from tests.unit.continuous.test_capture_admission import transcript
from tests.unit.continuous.test_runtime import config, make

from soc_agent.continuous.capture import sealed_jobs
from soc_agent.continuous.native import service
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.tcx_producer import TCXProducer


@pytest.mark.asyncio
async def test_bound_ack_allows_stop_after_socket_closed(tmp_path):
    source = TCXProducer(config(tmp_path))
    # The receiver validates Namespace/generation/policy before setting this event.
    source.remote_cleanup = "VERIFIED"
    source.stop_ack.set()
    await source.close()
    await source.request_stop()
    assert source.socket is None and source.remote_cleanup == "VERIFIED"


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup", ["UNKNOWN", "UNVERIFIED"])
async def test_closed_socket_never_fabricates_verified_cleanup(tmp_path, cleanup):
    source = TCXProducer(config(tmp_path))
    source.remote_cleanup = cleanup
    source.stop_ack.set()
    await source.close()
    with pytest.raises(ValueError, match="REMOTE_CLEANUP_UNVERIFIED"):
        await source.request_stop()


@pytest.mark.asyncio
async def test_no_ack_does_not_authorize_disconnected_stop(tmp_path):
    source = TCXProducer(config(tmp_path))
    source.remote_cleanup = "VERIFIED"  # a string is not an authenticated ACK
    with pytest.raises(ValueError, match="CONNECTED_OWNER"):
        await source.request_stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_kind", ["signal", "cli"])
async def test_native_shutdown_receives_final_seal_before_closing(tmp_path, monkeypatch, stop_kind):
    """Run the production service; mock only installed authority and Root transport."""
    directory, store = make(tmp_path)
    entered, stopping, acknowledged = asyncio.Event(), asyncio.Event(), asyncio.Event()
    order = []

    class Source:
        state = "RUNNING"
        snapshot = {}
        remote_cleanup = "UNKNOWN"

        async def events(self):
            entered.set()
            await stopping.wait()
            order.append("final_seal_received")
            yield {"kind": "native_seal"}  # transport boundary; no forged model input
            self.remote_cleanup = "VERIFIED"
            order.append("bound_ack_received")
            acknowledged.set()

        async def request_stop(self):
            order.append("owner_stop_requested")
            stopping.set()
            await asyncio.wait_for(acknowledged.wait(), 2)

        async def close(self):
            order.append("socket_closed")

    source = Source()
    runtime = ContinuousRuntime(directory, source=source)
    runtime.config = runtime.config.model_copy(update={"source": "NATIVE_SERVICE"})
    monkeypatch.setattr("soc_agent.continuous.service.require_source_authority", lambda _: None)

    async def observe(raw):
        assert raw == {"kind": "native_seal"}
        order.append("final_seal_persisted")

    monkeypatch.setattr(runtime, "observe", observe)
    task = asyncio.create_task(runtime.run())
    await asyncio.wait_for(entered.wait(), 3)
    if stop_kind == "signal":
        runtime.stop.set()  # exactly the installed CLI's SIGTERM handler
    else:
        store.control(stop=True)
    await asyncio.wait_for(task, 5)
    assert order.index("owner_stop_requested") < order.index("final_seal_persisted")
    assert order.index("final_seal_persisted") < order.index("bound_ack_received")
    assert order.index("bound_ack_received") < order.index("socket_closed")
    assert order.count("owner_stop_requested") == 1
    assert store.state()["cleanup"] == store.state()["collector_cleanup"] == "VERIFIED"
    assert runtime.metrics["predictions"] == 0


@pytest.mark.asyncio
async def test_native_signal_stop_ack_failure_is_preserved(tmp_path, monkeypatch):
    directory, store = make(tmp_path)
    entered = asyncio.Event()

    class Source:
        state = "RUNNING"
        snapshot = {}
        remote_cleanup = "UNKNOWN"

        async def events(self):
            entered.set()
            await asyncio.Event().wait()
            if False:
                yield None

        async def request_stop(self):
            raise TimeoutError("BOUND_STOP_ACK_MISSING")

        async def close(self):
            pass

    runtime = ContinuousRuntime(directory, source=Source())
    runtime.config = runtime.config.model_copy(update={"source": "NATIVE_SERVICE"})
    monkeypatch.setattr("soc_agent.continuous.service.require_source_authority", lambda _: None)
    task = asyncio.create_task(runtime.run())
    await asyncio.wait_for(entered.wait(), 3)
    runtime.stop.set()
    with pytest.raises(TimeoutError, match="BOUND_STOP_ACK_MISSING"):
        await asyncio.wait_for(task, 5)
    state = store.state()
    assert state["cleanup"] == "UNVERIFIED" and state["collector_cleanup"] == "UNKNOWN"
    assert "BOUND_STOP_ACK_MISSING" in state["last_error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("prior_completed_worker", [False, True])
async def test_normal_stop_during_native_model_approval_wait(tmp_path, prior_completed_worker):
    directory, store = make(tmp_path)
    # Native-shaped complete evidence, explicitly synthetic; no Action grant is created.
    job = sealed_jobs(*transcript())[0][0]
    store.enqueue(job)
    runtime = ContinuousRuntime(directory)
    prior_process = None
    if prior_completed_worker:
        prior_process = await asyncio.create_subprocess_exec(
            "/usr/bin/true", start_new_session=True
        )
        await prior_process.wait()
        runtime.analysis.process = prior_process
        runtime.analysis.cleanup = "VERIFIED"
    task = asyncio.create_task(runtime.run())
    try:
        async with asyncio.timeout(5):
            while runtime.worker_state != "WAITING_EXACT_MODEL_ACTION_APPROVAL":
                await asyncio.sleep(0.01)
        assert runtime.analysis.process is prior_process
        store.control(stop=True)
        await asyncio.wait_for(task, 5)
        state = store.state()
        assert state["state"] == "STOPPED" and state["cleanup"] == "VERIFIED"
        assert runtime.approval_wait_cancelled
        assert runtime.metrics["predictions"] == 0 and runtime.metrics["model_errors"] == 0
        assert store.queue.counts() == {"POISON": 1}  # no automatic replay/admission
        assert list((directory / "inputs").glob("*.json"))
        assert state["collector_cleanup"] == "NOT_APPLICABLE_REPLAY"
    finally:
        runtime.stop.set()
        if not task.done():
            await asyncio.wait_for(task, 5)


@pytest.mark.parametrize("code", [errno.EACCES, errno.ENOMEM, errno.EIO])
def test_provider_preserves_native_load_errno(monkeypatch, code):
    lib = Mock()

    def denied(*args):
        ctypes.set_errno(code)
        return None

    lib.continuous_open.side_effect = denied
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: lib)
    monkeypatch.setattr(service.socket, "if_nametoindex", lambda name: 1)
    with pytest.raises(OSError, match="ATTACH_FAILED_NO_RETRY") as result:
        service.Provider({"namespace": "net:[4026532232]"}, lambda body: None)
    assert result.value.errno == code


def test_provider_cleanup_failure_still_overrides_load_error(monkeypatch):
    lib = Mock()

    def denied(*args):
        ctypes.set_errno(errno.EUCLEAN)
        return None

    lib.continuous_open.side_effect = denied
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: lib)
    monkeypatch.setattr(service.socket, "if_nametoindex", lambda name: 1)
    with pytest.raises(ValueError, match="ATTACH_CLEANUP_UNVERIFIED"):
        service.Provider({"namespace": "net:[4026532232]"}, lambda body: None)


def test_service_entry_preserves_original_exception_without_crash_reporter():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-I", service.__file__],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert proc.returncode != 0 and "INSTALLATION_REQUIRED" in proc.stderr
    assert "Error in sys.excepthook" not in proc.stderr
    assert "/var/crash" not in proc.stderr


def test_failed_kernel_attach_never_publishes_ready_socket(tmp_path, monkeypatch):
    """Execute run(), mocking only its privileged installation/system boundaries."""
    import importlib.util
    import os
    import sys
    from pathlib import Path
    from types import SimpleNamespace

    policy = {"namespace": "net:[4026532232]", "uid": 1000, "files": {"continuous.bpf.o": "a" * 64}}
    installed = SimpleNamespace(
        installed=lambda: policy, root_file=lambda _: b"policy", validate=lambda _: None
    )
    installed_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None))
    server = Mock()
    failed = Mock(side_effect=PermissionError(errno.EACCES, "KERNEL_VERIFIER_REJECTED"))
    original_lstat = Path.lstat
    original_read = Path.read_text
    original_open = os.open

    def trusted_stat(path, *args, **kwargs):
        row = original_lstat(
            tmp_path if str(path) == "/run/soc-agent-continuous" else path, *args, **kwargs
        )
        return SimpleNamespace(st_uid=0, st_mode=row.st_mode & ~0o022)

    def audit_open(path, flags, *args):
        return original_open(tmp_path / "root-audit.jsonl", flags, *args)

    with monkeypatch.context() as boundary:
        boundary.setattr(service, "INSTALL", tmp_path)
        boundary.setattr(service, "__file__", str(tmp_path / "service.py"))
        (tmp_path / "service.py").touch()
        (tmp_path / "policy.py").touch()
        boundary.setattr(service.os, "geteuid", lambda: 0)
        boundary.setattr(service.os, "readlink", lambda _: policy["namespace"])
        boundary.setattr(Path, "lstat", trusted_stat)
        boundary.setattr(
            Path,
            "read_text",
            lambda p, *a, **kw: (
                "" if str(p).startswith("/proc/self/net/") else original_read(p, *a, **kw)
            ),
        )
        boundary.setattr(importlib.util, "spec_from_file_location", lambda *a: installed_spec)
        boundary.setattr(importlib.util, "module_from_spec", lambda _: installed)
        boundary.setattr(sys, "flags", SimpleNamespace(isolated=True))
        for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"):
            boundary.delenv(name, raising=False)
        boundary.setattr(service, "resource_scope", lambda: None)
        boundary.setattr(service.socket, "if_nameindex", lambda: [(1, "lo")])
        boundary.setattr(service.socket, "socket", lambda *a: server)
        boundary.setattr(service.signal, "signal", lambda *a: None)
        boundary.setattr(service.os, "open", audit_open)
        original_fstat = os.fstat
        boundary.setattr(
            service.os,
            "fstat",
            lambda fd: SimpleNamespace(st_uid=0, st_mode=0o600, st_size=original_fstat(fd).st_size),
        )
        boundary.setattr(service, "Provider", failed)
        with pytest.raises(PermissionError, match="KERNEL_VERIFIER_REJECTED"):
            service.run()
    failed.assert_called_once()
    server.bind.assert_not_called()
    server.listen.assert_not_called()
    server.close.assert_called_once()
    rows = [
        __import__("json").loads(line)
        for line in (tmp_path / "root-audit.jsonl").read_text().splitlines()
    ]
    assert [row["code"] for row in rows] == ["ATTACH_REQUESTED", "SERVICE_STOPPED"]
    assert all(row["state"]["state"] != "RUNNING" for row in rows)


@pytest.mark.asyncio
async def test_runtime_does_not_promote_remote_collector_cleanup(tmp_path):
    from types import SimpleNamespace

    directory, _ = make(tmp_path)
    runtime = ContinuousRuntime(directory)
    runtime.config = runtime.config.model_copy(update={"source": "NATIVE_SERVICE"})
    runtime.source = SimpleNamespace(state="STOPPED", snapshot={}, remote_cleanup="UNVERIFIED")
    value = runtime.snapshot()
    assert value["collector_cleanup"] == "UNVERIFIED"
    assert value["collection_live"] is False
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_unrequested_worker_cancel_remains_unknown_failure(tmp_path):
    directory, store = make(tmp_path)
    store.enqueue(sealed_jobs(*transcript())[0][0])
    runtime = ContinuousRuntime(directory)
    task = asyncio.create_task(runtime.consume())
    try:
        async with asyncio.timeout(5):
            while runtime.worker_state != "WAITING_EXACT_MODEL_ACTION_APPROVAL":
                await asyncio.sleep(0.01)
        task.cancel()  # no user Stop: never classify this as normal approval-wait shutdown
        with pytest.raises(asyncio.CancelledError):
            await task
        assert runtime.approval_wait_cancelled is False
        assert store.queue.counts() == {"POISON": 1}
        assert runtime.analysis.process is None and runtime.metrics["predictions"] == 0
    finally:
        runtime.stop.set()
        await runtime.analysis.close()
