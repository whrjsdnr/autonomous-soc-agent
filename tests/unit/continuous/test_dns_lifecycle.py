"""Real ordinary child + AF_UNIX; AF_PACKET/Namespace authority is simulated only.

These are protocol/lifecycle tests, never Native or DNS traffic verification.
"""

import asyncio
import hashlib
import json
import subprocess
import sys
import time

import pytest
from tests.unit.continuous.test_dns_source import prepared

from soc_agent.continuous import dns_source
from soc_agent.security_ai.operational.network_capture import helper_transport


@pytest.mark.asyncio
async def test_owner_stop_before_helper_admission_verifies_only_local_listener(
    tmp_path, monkeypatch
):
    directory, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    source = dns_source.DNSProducer(directory, pin)

    async def consume():
        return [packet async for packet in source.events()]

    task = asyncio.create_task(consume())
    try:
        while source._handshake_task is None:
            await asyncio.sleep(0.01)
        await source.request_stop()
        assert await asyncio.wait_for(task, 3) == []
        assert source.last_error is None and source.state == "STOPPED"
        assert source.cleanup == "VERIFIED"
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["cleanup_scope"] == "LOCAL_DNS_LISTENER_ONLY_NO_AUTHENTICATED_HELPER"
        assert proof["helper_cleanup"] == "NOT_OBSERVED_NO_AUTHENTICATED_HELPER"
        assert proof["handshake_joined"] and proof["listener_closed"] and proof["channel_closed"]
        assert not proof["authenticated_closed"] and not proof["stream_completion_verified"]
        assert proof["closed_sha256"] is None and proof["global_kernel_cleanup"] == "UNKNOWN"
        assert source.snapshot["cleanup_scope"] == proof["cleanup_scope"]
        assert not (directory / "verified-ready.json").exists()
        assert not (directory / "verified-closed.json").exists()
        before = (directory / "cleanup.json").read_bytes()
        await source.request_stop()
        assert (directory / "cleanup.json").read_bytes() == before
    finally:
        await source.close()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_unrequested_listener_close_is_not_successful_owner_stop(tmp_path, monkeypatch):
    directory, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    source = dns_source.DNSProducer(directory, pin)
    source.capture.close()  # Unexpected transport closure, no owner Stop intent.
    with pytest.raises(ValueError, match="HELPER_LISTENER_CLOSED"):
        await anext(source.events())
    assert source.state == "FAILED" and source.cleanup != "VERIFIED"
    assert source.last_error == "CaptureUnavailable:HELPER_LISTENER_CLOSED"


@pytest.mark.asyncio
async def test_owner_stop_does_not_hide_racing_peer_identity_failure(tmp_path, monkeypatch):
    import threading

    directory, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    source = dns_source.DNSProducer(directory, pin)
    entered = threading.Event()

    def rejected_peer():
        entered.set()
        assert source.capture.closed.wait(2)
        raise dns_source.CaptureUnavailable("HELPER_PEER_IDENTITY_MISMATCH")

    monkeypatch.setattr(source.capture, "handshake", rejected_peer)
    task = asyncio.create_task(anext(source.events()))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        await source.request_stop()
        with pytest.raises(ValueError, match="HELPER_PEER_IDENTITY_MISMATCH"):
            await asyncio.wait_for(task, 3)
        assert source.last_error == "CaptureUnavailable:HELPER_PEER_IDENTITY_MISMATCH"
        assert source.cleanup == "UNVERIFIED"
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["handshake_joined"] and proof["helper_cleanup"] == "UNVERIFIED"
        assert proof["cleanup"] == "UNVERIFIED" and not proof["authenticated_closed"]
    finally:
        await source.close()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_runtime_stop_while_dns_helper_not_started_keeps_primary_error(tmp_path, monkeypatch):
    from tests.unit.continuous.test_runtime import make

    from soc_agent.continuous.service import ContinuousRuntime

    directory, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    source = dns_source.DNSProducer(directory, pin)
    runtime_path, _ = make(tmp_path)
    runtime = ContinuousRuntime(runtime_path, dns_source=source)
    task = asyncio.create_task(runtime.run())
    try:
        while source._handshake_task is None and not task.done():
            await asyncio.sleep(0.01)
        assert not task.done()
        runtime.last_error = "PRESERVED_LAUNCHER_READY_FAILURE"
        runtime.stop.set()
        await asyncio.wait_for(task, 10)
        state = runtime.store.state()
        assert state["last_error"] == "PRESERVED_LAUNCHER_READY_FAILURE"
        assert state["cleanup"] == "VERIFIED"
        assert state["dns_transport"]["helper_cleanup"] == "NOT_OBSERVED_NO_AUTHENTICATED_HELPER"
        assert state["orchestration"]["worker"]["state"] == "STOPPED"
    finally:
        runtime.stop.set()
        await asyncio.gather(task, return_exceptions=True)


def test_stop_intent_precedes_immediate_ack_and_is_sent_once(tmp_path, monkeypatch):
    directory, session, _ = prepared(tmp_path)
    capture = dns_source.DNSCapture(directory, session)
    calls = []

    def immediate_ack(self):
        calls.append(self.stop_requested_unix)
        self.terminal_observed_unix = time.time()

    monkeypatch.setattr(dns_source.TotalCapture, "request_stop", immediate_ack)
    capture.channel = object()  # Only the send boundary is mocked.
    try:
        capture.request_stop()
        capture.request_stop()
        assert len(calls) == 1
        assert calls[0] <= capture.terminal_observed_unix
        assert capture.stop_send_error is None
    finally:
        capture.channel = None
        capture.close()


def test_stop_send_failure_is_preserved_without_duplicate_attempt(tmp_path, monkeypatch):
    directory, session, _ = prepared(tmp_path)
    capture = dns_source.DNSCapture(directory, session)
    calls = []

    def disconnected(self):
        calls.append(self.stop_requested_unix)
        raise dns_source.CaptureUnavailable("STREAM_STOP_DISCONNECTED")

    monkeypatch.setattr(dns_source.TotalCapture, "request_stop", disconnected)
    capture.channel = object()
    try:
        for _ in range(2):
            with pytest.raises(ValueError, match="STREAM_STOP_DISCONNECTED"):
                capture.request_stop()
        assert len(calls) == 1 and calls[0] is not None
        assert capture.stop_send_error == "STREAM_STOP_DISCONNECTED"
        assert capture.terminal is None
    finally:
        capture.channel = None
        capture.close()


CHILD = r"""
import os,select,socket,sys,time
from pathlib import Path
from soc_agent.continuous.dns_source import DNSSession,DNSMessage
from soc_agent.security_ai.operational.network_capture.live_helper import process_start
s=DNSSession.model_validate_json(Path(sys.argv[1]).read_bytes())
mode=sys.argv[2]; c=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
c.connect(s.socket_address); seq=1; total=sent=0; began=time.monotonic()
caps=dict(euid=s.uid,egid=s.gid,CapEff=0,CapPrm=0,CapInh=0,CapAmb=0,CapBnd=8192,NoNewPrivs=1)
def send(kind,**kw):
 c.sendall(DNSMessage(kind=kind,session_id=s.session_id,counter_sequence=seq,
  kernel_packets=kw.pop("interval",0),capture_drops=0,kernel_packets_total=total,capture_drops_total=0,
  counter_status="COUNTER_VERIFIED",received_frames=total,sent_packets=sent,**kw).model_dump_json().encode())
send("READY",pid=os.getpid(),process_start=process_start(os.getpid()),capabilities=caps)
if mode=="crash":
 time.sleep(.1);os._exit(7)
while time.monotonic()-began<(15 if mode=="ignore_stop" else 7):
 if select.select([c],[],[],.05)[0]:
  if c.recv(64)==b"STOP":
   if mode=="ignore_stop": continue
   if mode=="no_ack": os._exit(7)
   if mode=="delayed_ack": time.sleep(.2)
   if mode=="slow_capture_close": time.sleep(2.2)
   if mode=="quarantine":
    from types import SimpleNamespace
    from tests.total_monitoring_support import dns_packet
    from soc_agent.security_ai.research.live_input import timestamp_ns
    p=dns_packet(SimpleNamespace(session=s),1)
    p=p.model_copy(update=dict(timestamp_origin="KERNEL_SO_TIMESTAMPNS",capture_timestamp_ns=timestamp_ns(p)))
    seq+=1;total=1;send("HEARTBEAT",interval=1)
    sent=1;send("PACKET",sequence=1,packet=p)
   if mode!="bad_ack": seq+=1
   send("CLOSED",capabilities=caps,elapsed_seconds=time.monotonic()-began)
   if mode in ("slow_process_exit", "process_exit_missing"):
    time.sleep(1.3 if mode=="slow_process_exit" else 7)
   c.close();sys.exit(0)
 if mode=="normal":
  seq+=1;send("HEARTBEAT")
c.close();sys.exit(8)
"""


async def started(tmp_path, monkeypatch, mode):
    directory, session, pin = prepared(tmp_path)
    monkeypatch.setattr(dns_source, "load", lambda _: session)
    monkeypatch.setattr(helper_transport, "validate_peer", lambda *a, **kw: None)
    source = dns_source.DNSProducer(directory, pin)
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(directory / "session.json"), mode],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    async def consume():
        values = []
        async for packet in source.events():
            values.append(packet)
        return values

    task = asyncio.create_task(consume())
    deadline = time.monotonic() + 3
    while source.state != "RUNNING" and not task.done() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    assert source.state == "RUNNING"
    assert source.capture.ready.pid == child.pid
    assert source.capture.process_observation()["state"] == "ALIVE"
    return directory, source, child, task


async def reap(source, child, task):
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await source.close()
    if child.poll() is None:
        child.terminate()  # Only the ordinary fake helper child created by this test.
    child.wait(timeout=3)
    child.stdout.close()
    child.stderr.close()


@pytest.mark.asyncio
async def test_normal_stop_ack_process_exit_socket_cleanup_and_restart_guard(tmp_path, monkeypatch):
    directory, source, child, task = await started(tmp_path, monkeypatch, "normal")
    try:
        pin = hashlib.sha256((directory / "session.json").read_bytes()).hexdigest()
        ready_before = (directory / "verified-ready.json").read_bytes()
        with pytest.raises(ValueError, match="SESSION_ALREADY_ADMITTED"):
            dns_source.DNSProducer(directory, pin)
        assert child.poll() is None and source.state == "RUNNING"
        assert (directory / "verified-ready.json").read_bytes() == ready_before
        await source.request_stop()
        assert await asyncio.wait_for(task, 3) == []
        assert child.wait(timeout=2) == 0
        assert source.state == "STOPPED" and source.cleanup == "VERIFIED"
        source.capture.last_heartbeat = time.monotonic() - 30
        view = source.snapshot
        assert view["heartbeat_status"] == "ENDED_AUTHENTICATED_CLOSED"
        assert view["helper_process"]["state"] == "EXITED"
        assert view["helper_process"]["exit_code"] is None  # Not this receiver's child.
        assert view["transport_error"] is None
        assert view["closed_observed_unix"] >= view["stop_requested_unix"]
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["cleanup"] == "VERIFIED"
        assert proof["channel_closed"] and proof["listener_closed"] and proof["reader_joined"]
        assert proof["global_kernel_cleanup"] == "UNKNOWN"
        original = (directory / "cleanup.json").read_bytes()
        pin = hashlib.sha256((directory / "session.json").read_bytes()).hexdigest()
        with pytest.raises(ValueError, match="SESSION_ALREADY_ADMITTED"):
            dns_source.DNSProducer(directory, pin)
        await source.close()
        assert (directory / "cleanup.json").read_bytes() == original
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["delayed", "quarantine", "no_ack", "bad_ack"])
async def test_delayed_heartbeat_stops_admission_but_drains_owned_cleanup(
    tmp_path, monkeypatch, mode
):
    directory, source, child, task = await started(tmp_path, monkeypatch, mode)
    acknowledged = mode in {"delayed", "quarantine"}
    try:
        source.capture.last_heartbeat = time.monotonic() - 3
        with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
            await asyncio.wait_for(task, 7)
        assert child.wait(timeout=2) == (7 if mode == "no_ack" else 0)
        assert (
            source.state == "FAILED"
            and source.capture.reader_error == "HELPER_HEARTBEAT_OR_PROCESS_STALE"
        )
        assert source.cleanup == ("VERIFIED" if acknowledged else "UNVERIFIED")
        assert not source.capture.completion_verified()  # Stream integrity never promoted.
        assert source.received == source.capture.delivered == 0
        assert source.capture.quarantined_packets == int(mode == "quarantine")
        assert not source.capture.is_live()
        assert source.capture.process_observation()["state"] == "EXITED"
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["capture_admission"] == "DENIED_AFTER_FAILURE"
        assert proof["first_error"] == source.last_error
        assert proof["authenticated_closed"] is acknowledged
        assert proof["channel_closed"] and proof["listener_closed"] and proof["reader_joined"]
        assert proof["global_kernel_cleanup"] == "UNKNOWN"
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_actual_abnormal_process_exit_is_not_mislabeled_heartbeat_stale(
    tmp_path, monkeypatch
):
    directory, source, child, task = await started(tmp_path, monkeypatch, "crash")
    try:
        with pytest.raises(ValueError, match="DISCONNECTED_OR_RECORD_LIMIT"):
            await asyncio.wait_for(task, 3)
        assert child.wait(timeout=2) == 7
        assert source.last_error == "CaptureUnavailable:HELPER_DISCONNECTED_OR_RECORD_LIMIT"
        assert source.cleanup == "UNVERIFIED"
        assert source.capture.process_observation()["state"] == "EXITED"
        assert not (directory / "verified-closed.json").exists()
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["normal", "delayed"])
async def test_cleanup_audit_failure_never_overwrites_primary_or_claims_commit(
    tmp_path, monkeypatch, mode
):
    directory, source, child, task = await started(tmp_path, monkeypatch, mode)

    def disk_full(*_):
        raise OSError(28, "fixture disk full")

    monkeypatch.setattr(dns_source, "write_cleanup", disk_full)
    try:
        if mode == "normal":
            await source.request_stop()
            with pytest.raises(OSError) as result:
                await asyncio.wait_for(task, 3)
            assert result.value.errno == 28
        else:
            source.capture.last_heartbeat = time.monotonic() - 3
            with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
                await asyncio.wait_for(task, 7)
            assert "HEARTBEAT_OR_PROCESS_STALE" in source.last_error
        assert child.wait(timeout=2) == 0
        assert source.cleanup == "UNVERIFIED" and source.state == "FAILED"
        assert source.cleanup_evidence_sha256 is None
        assert source.cleanup_error.startswith("OSError:")
        assert not (directory / "cleanup.json").exists()
        assert source.capture.listener.fileno() == source.capture.channel.fileno() == -1
    finally:
        await reap(source, child, task)


def test_supervisor_exposes_dns_first_error_while_cleanup_is_pending(tmp_path):
    from types import SimpleNamespace

    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous.service import ContinuousRuntime
    from soc_agent.continuous.store import Store

    directory = tmp_path / "runtime"
    Store.create(directory, config(tmp_path))
    error = "CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE"
    dns = SimpleNamespace(last_error=error, snapshot=dict(state="FAILED", cleanup="PENDING"))
    runtime = ContinuousRuntime(directory, dns_source=dns)
    assert runtime.last_error is None
    assert runtime.snapshot()["last_error"] == error
    runtime.last_error = "OLDER_PRIMARY_ERROR"
    assert runtime.snapshot()["last_error"] == "OLDER_PRIMARY_ERROR"


@pytest.mark.asyncio
async def test_failed_failure_log_keeps_first_error_and_cleanup_unverified(tmp_path, monkeypatch):
    directory, source, child, task = await started(tmp_path, monkeypatch, "delayed")
    original = helper_transport.write_private

    def failed_diagnostic(path, value):
        if path.name == "transport-failure.json":
            raise OSError(28, "fixture disk full")
        original(path, value)

    monkeypatch.setattr(helper_transport, "write_private", failed_diagnostic)
    try:
        source.capture.last_heartbeat = time.monotonic() - 3
        with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
            await asyncio.wait_for(task, 7)
        assert child.wait(timeout=2) == 0
        assert source.capture.reader_error == "HELPER_HEARTBEAT_OR_PROCESS_STALE"
        assert source.capture.reader_diagnostic_error == "HELPER_TRANSPORT_DIAGNOSTIC_WRITE_FAILED"
        assert source.cleanup == "UNVERIFIED"
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["transport_diagnostic_error"] == source.capture.reader_diagnostic_error
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_real_two_second_silence_is_not_an_initial_process_exit(tmp_path, monkeypatch):
    directory, source, child, task = await started(tmp_path, monkeypatch, "delayed")
    try:
        began = time.monotonic()
        assert child.poll() is None and source.capture.process_observation()["state"] == "ALIVE"
        with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
            await asyncio.wait_for(task, 6)
        assert 1.8 < time.monotonic() - began < 5
        assert child.wait(timeout=2) == 0
        assert source.state == "FAILED" and source.cleanup == "VERIFIED"
        assert source.last_error_observed_unix >= source.capture.last_heartbeat_unix + 1.9
        assert source.snapshot["heartbeat_status"] == "ENDED_AFTER_STREAM_FAILURE"
        assert source.snapshot["helper_process"]["state"] == "EXITED"
        assert not source.capture.completion_verified()
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_missing_ack_has_bounded_drain_and_no_receiver_process_kill(tmp_path, monkeypatch):
    directory, source, child, task = await started(tmp_path, monkeypatch, "ignore_stop")
    try:
        source.capture.last_heartbeat = time.monotonic() - 3
        began = time.monotonic()
        with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
            await asyncio.wait_for(task, 10)  # Existing owner shutdown includes durable Audit.
        assert time.monotonic() - began >= 4.9
        # Measure the unchanged five-second ACK phase, not Audit fsync latency.
        assert 4.9 <= source.capture.failure_stop_elapsed_seconds < 6
        assert source.cleanup == "UNVERIFIED"
        assert source.capture.failure_stop_error == "CONTINUOUS_DNS_FAILURE_STOP_ACK_MISSING"
        assert child.poll() is None  # The receiver never signals a service-owned PID.
        proof = json.loads((directory / "cleanup.json").read_text())
        assert not proof["authenticated_closed"] and not proof["stream_completion_verified"]
        assert proof["reader_joined"] and proof["channel_closed"]
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_owner_stop_joins_in_progress_failure_ack_without_false_cleanup_failure(
    tmp_path, monkeypatch
):
    directory, source, child, task = await started(tmp_path, monkeypatch, "delayed_ack")
    try:
        source.capture.last_heartbeat = time.monotonic() - 3
        deadline = time.monotonic() + 2
        while source.capture.reader_error is None and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert source.capture.reader_error == "HELPER_HEARTBEAT_OR_PROCESS_STALE"
        await source.request_stop()
        with pytest.raises(ValueError, match="HEARTBEAT_OR_PROCESS_STALE"):
            await asyncio.wait_for(task, 3)
        assert child.wait(timeout=2) == 0
        assert source.cleanup == "VERIFIED" and source.state == "FAILED"
        assert source.capture.terminal is not None
        assert source.capture.failure_stop_error is None
        assert not source.capture.completion_verified()
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_cancelled_cleanup_joins_owned_audit_writer_without_success_claim(
    tmp_path, monkeypatch
):
    import threading

    directory, source, child, task = await started(tmp_path, monkeypatch, "normal")
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    original = dns_source.write_cleanup

    def delayed(*args):
        entered.set()
        assert release.wait(3)
        result = original(*args)
        completed.set()
        return result

    monkeypatch.setattr(dns_source, "write_cleanup", delayed)
    try:
        await source.request_stop()
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0.03)
        assert not task.done() and not completed.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert completed.is_set() and child.wait(timeout=2) == 0
        assert source.cleanup == "UNVERIFIED" and source.state == "FAILED"
        assert source.cleanup_evidence_sha256 is None
        assert source.cleanup_error == "CANCELLED_DURING_CLEANUP_COMMIT"
    finally:
        release.set()
        await reap(source, child, task)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["slow_capture_close", "slow_process_exit"])
async def test_stop_budget_covers_closed_and_exit_without_false_heartbeat_failure(
    tmp_path, monkeypatch, mode
):
    directory, source, child, task = await started(tmp_path, monkeypatch, mode)
    began = time.monotonic()
    try:
        await source.request_stop()
        assert await asyncio.wait_for(task, 5.5) == []
        assert child.wait(timeout=1) == 0
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["ack_order_verified"]
        assert proof["cleanup"] == source.cleanup == "VERIFIED"
        assert source.last_error is source.capture.reader_error is None
        assert proof["stop_requested_monotonic"] <= proof["cleanup_deadline_monotonic"]
        assert proof["cleanup_deadline_monotonic"] - proof["stop_requested_monotonic"] == 5
        assert time.monotonic() - began < 5
        assert proof["helper_process"]["state"] in {"EXITED", "EXITED_ZOMBIE"}
    finally:
        await reap(source, child, task)


@pytest.mark.asyncio
async def test_closed_without_process_exit_remains_unverified_at_shared_deadline(
    tmp_path, monkeypatch
):
    directory, source, child, task = await started(tmp_path, monkeypatch, "process_exit_missing")
    began = time.monotonic()
    try:
        await source.request_stop()
        assert await asyncio.wait_for(task, 5.5) == []
        proof = json.loads((directory / "cleanup.json").read_text())
        assert proof["authenticated_closed"] and proof["ack_order_verified"]
        assert proof["helper_process"]["state"] == "ALIVE"
        assert proof["cleanup"] == "UNVERIFIED"
        assert 4.5 <= time.monotonic() - began < 5.5
        before = (directory / "cleanup.json").read_bytes()
        await source.close()
        assert (directory / "cleanup.json").read_bytes() == before
    finally:
        await reap(source, child, task)
