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
