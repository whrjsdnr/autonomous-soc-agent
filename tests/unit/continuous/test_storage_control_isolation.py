"""Control stays observable through data stalls; no Root, capture or external API."""

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.cli import code_identity, observed_status, request_stop
from soc_agent.continuous.process_identity import runtime_identity
from soc_agent.continuous.service import ContinuousRuntime


class NativeBoundary:
    state = "RUNNING"
    snapshot = {}
    failure = None

    def __init__(self):
        self.stop_sent = asyncio.Event()

    async def request_stop(self):
        self.stop_sent.set()


def runtime(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    directory, _ = make(tmp_path)
    value = ContinuousRuntime(directory)
    value.config = value.config.model_copy(update={"source": "NATIVE_SERVICE"})
    value.source = NativeBoundary()
    # Configuration stays REPLAY in the isolated Store: this test cannot attest
    # or start a Native runtime. Inspect the atomic record as display evidence.
    return directory, value


def replay_runtime(tmp_path):
    # The shared make() fixture intentionally has malformed input for source-error
    # tests. These lifecycle tests require one valid excluded Replay observation.
    directory, store = make(tmp_path)
    body = (
        json.dumps(dict(sequence=1, id=str(uuid4()), kind="excluded", affects_integrity=False))
        + "\n"
    ).encode()
    store.config.input_file.write_bytes(body)
    config = store.config.model_copy(update={"input_sha256": hashlib.sha256(body).hexdigest()})
    # Recreate only this test-owned empty Runtime with the pinned valid input.
    import shutil

    shutil.rmtree(directory)
    from soc_agent.continuous.store import Store

    return directory, Store.create(directory, config)


def shown(directory):
    return json.loads((directory / "observation.json").read_text())["snapshot"]


@pytest.mark.asyncio
async def test_dns_status_reader_lock_does_not_block_control_or_stop(tmp_path):
    directory, service = runtime(tmp_path)
    entered, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    reader_threads = []

    class SlowDNSStatus:
        last_error = None

        @property
        def snapshot(self):
            reader_threads.append(threading.get_ident())
            assert threading.get_ident() != loop_thread, "DNS_STATUS_BLOCKED_EVENT_LOOP"
            entered.set()
            assert release.wait(3)
            return {"state": "RUNNING", "cleanup": "NOT_STARTED"}

    service.dns_source = SlowDNSStatus()
    pending = asyncio.create_task(service.observed_snapshot())
    control = asyncio.create_task(service.control())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        await asyncio.sleep(0.4)
        value = shown(directory)
        assert value["control"]["sequence"] >= 2
        assert value["dns_transport"]["state"] == "UNKNOWN_STALE_OBSERVATION"
        assert time.monotonic() - value["control"]["monotonic"] < 2
        assert not pending.done() and not control.done()
        service.stop.set()
        await asyncio.wait_for(service.source.stop_sent.wait(), 0.5)
        assert not pending.done()  # STOP does not wait for DNS status lock release.
    finally:
        release.set()
        await pending
        service.stop.set()
        await control
    assert len(reader_threads) == 1 and reader_threads[0] != loop_thread


def test_cached_dns_status_never_claims_stale_running_or_verified_cleanup(tmp_path):
    _, service = runtime(tmp_path)
    service.dns_source = SimpleNamespace(last_error="ORIGINAL_DNS_FAILURE")
    service.cached_dns_transport = {"state": "RUNNING", "cleanup": "VERIFIED"}
    service.cached_dns_observed_monotonic = time.monotonic() - 3
    view = service.control_dns_snapshot()
    assert view["state"] == "UNKNOWN_STALE_OBSERVATION"
    assert view["cleanup"] == "UNVERIFIED_STATUS_OBSERVATION"
    assert view["status_scope"] == "CACHED_DISPLAY_NOT_ADMISSION"
    assert service.cached_dns_transport == {"state": "RUNNING", "cleanup": "VERIFIED"}
    assert service.snapshot(dns_transport=view)["last_error"] == "ORIGINAL_DNS_FAILURE"
    service.cached_dns_observed_monotonic = time.monotonic()
    assert service.control_dns_snapshot()["state"] == "RUNNING"


@pytest.mark.asyncio
async def test_ten_second_write_does_not_block_heartbeat_or_stop(tmp_path):
    directory, service = runtime(tmp_path)
    entered = threading.Event()

    def slow_write():
        entered.set()
        time.sleep(10)

    pending = asyncio.create_task(service.storage(slow_write))
    assert await asyncio.to_thread(entered.wait, 1)
    control = asyncio.create_task(service.control())
    sequences = []
    while time.monotonic() - service.storage_health["started_monotonic"] < 6:
        await asyncio.sleep(0.2)
        if (directory / "observation.json").exists():
            value = shown(directory)
            sequences.append(value["control"]["sequence"])
            assert time.monotonic() - value["control"]["monotonic"] < 2
    assert not pending.done() and not control.done()
    value = shown(directory)
    assert value["state"] == "DEGRADED" and value["control"]["data_stalled"]
    assert value["last_error"] is None
    assert (
        value["component_health"]["data_progress"]["reason"] == "CONTINUOUS_DATA_PROGRESS_STALLED"
    )
    assert not service.source.stop_sent.is_set()  # Slow data does not kill the Collector.
    assert service.control_health["error"] is None
    assert len(set(sequences)) >= 20
    service.stop.set()
    await asyncio.wait_for(service.source.stop_sent.wait(), 0.5)
    assert not pending.done()  # Explicit STOP still bypasses the slow write.
    await control
    await pending
    assert service.storage_health["max_operation"] == "slow_write"
    assert service.storage_health["max_seconds"] >= 10


@pytest.mark.parametrize("operation", ["queue_commit", "window_seal", "audit_flush"])
@pytest.mark.asyncio
async def test_slow_data_operations_do_not_serialize_control(tmp_path, operation):
    directory, service = runtime(tmp_path)
    control = asyncio.create_task(service.control())

    def slow():
        time.sleep(0.8)

    slow.__name__ = operation
    try:
        pending = asyncio.create_task(service.storage(slow))
        await asyncio.sleep(0.5)
        value = shown(directory)
        assert value["control"]["sequence"] >= 3
        assert value["component_health"]["storage"]["operation"] == operation
        assert not pending.done()
        await pending
    finally:
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_sqlite_exclusive_lock_does_not_block_control(tmp_path):
    directory, service = runtime(tmp_path)
    control = asyncio.create_task(service.control())
    try:
        with sqlite3.connect(directory / "queue.sqlite") as held:
            held.execute("BEGIN EXCLUSIVE")
            pending = asyncio.create_task(service.storage(service.store.queue.counts))
            await asyncio.sleep(0.7)
            value = shown(directory)
            assert value["control"]["sequence"] >= 4 and not pending.done()
            held.rollback()
        assert await pending == {}
    finally:
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_writer_failure_preserves_first_error_and_sends_stop(tmp_path, monkeypatch):
    _, service = runtime(tmp_path)
    service.last_error = "ORIGINAL_DATA_FAILURE"

    def fail(*args, **kwargs):
        raise OSError("INJECTED_ENOSPC")

    monkeypatch.setattr(service.store, "publish_observation", fail)
    with pytest.raises(OSError, match="ENOSPC"):
        await service.control()
    assert service.stop.is_set() and service.source.stop_sent.is_set()
    assert service.last_error == "ORIGINAL_DATA_FAILURE"
    assert "ENOSPC" in service.control_health["error"]


@pytest.mark.asyncio
async def test_slow_writer_expires_without_reusing_old_success(tmp_path, monkeypatch):
    directory, service = runtime(tmp_path)
    original = service.store.publish_observation

    def slow(value, **kwargs):
        time.sleep(5.3)
        original(value, **kwargs)

    monkeypatch.setattr(service.store, "publish_observation", slow)
    with pytest.raises(TimeoutError):
        await service.control()
    assert service.source.stop_sent.is_set() and service.stop.is_set()
    assert service.last_error == "CONTINUOUS_HEARTBEAT_PUBLICATION_FAILED"
    await service.control_writer  # A late writer must join before final durable state.
    assert time.monotonic() - shown(directory)["control"]["monotonic"] >= 5


@pytest.mark.asyncio
async def test_control_stop_does_not_wait_for_data_lock_or_ack(tmp_path):
    _, service = runtime(tmp_path)
    release = threading.Event()
    entered = threading.Event()

    def hold():
        entered.set()
        release.wait(3)

    pending = asyncio.create_task(service.storage(hold))
    assert await asyncio.to_thread(entered.wait, 1)
    control = asyncio.create_task(service.control())
    try:
        await asyncio.sleep(0.15)
        service.stop.set()
        await asyncio.wait_for(service.source.stop_sent.wait(), 0.5)
        assert not pending.done()
    finally:
        release.set()
        await pending
        await control
    assert shown(service.directory)["state"] == "STOPPING"


@pytest.mark.asyncio
async def test_window_progress_stall_not_confused_with_idle_traffic(tmp_path):
    directory, service = runtime(tmp_path)
    service.data_progress.update(
        active=True, operation="window_seal", started_monotonic=time.monotonic() - 6
    )
    control = asyncio.create_task(service.control())
    await asyncio.sleep(0.2)
    assert shown(directory)["state"] == "DEGRADED"
    assert shown(directory)["control"]["data_stalled"]
    assert service.last_error is None and not service.stop.is_set()
    service.data_progress.update(active=False, completed_monotonic=time.monotonic())
    await asyncio.sleep(0.2)
    assert shown(directory)["state"] == "RUNNING"
    assert not shown(directory)["control"]["data_stalled"]
    assert service.data_recovery_count == 1
    service.stop.set()
    await control
    _, idle = runtime(tmp_path / "idle")
    control = asyncio.create_task(idle.control())
    await asyncio.sleep(0.3)
    assert not idle.stop.is_set()  # no pending work is normal, even with zero events.
    idle.stop.set()
    await control


def control_snapshot(**updates):
    return (
        dict(
            state="RUNNING",
            source="JSONL_REPLAY",
            collector="RUNNING_REPLAY",
            worker="IDLE",
            heartbeat_unix=0,
            collection_live=False,
            cleanup="PENDING_SERVICE_STOP",
            control=dict(
                contract="soc-runtime-control:v1",
                identity=runtime_identity(os.getpid()),
                sequence=1,
                monotonic=time.monotonic(),
                lease_seconds=5,
                data_stalled=False,
            ),
        )
        | updates
    )


def test_monotonic_observer_clock_and_pid_reuse(tmp_path, monkeypatch):
    directory, store = make(tmp_path)
    store.update(control_snapshot())
    assert observed_status(directory)["state"] == "RUNNING"  # Wall stamp0 is not a monotonic age.
    value = control_snapshot()
    value["control"]["monotonic"] -= 6
    store.update(value)
    assert observed_status(directory)["state"] == "UNKNOWN_STALE_HEARTBEAT"
    store.update(control_snapshot())
    monkeypatch.setattr("soc_agent.continuous.process_identity.runtime_identity", lambda pid: {})
    assert observed_status(directory)["state"] == "UNKNOWN_STALE_HEARTBEAT"


def test_real_process_exit_is_not_running(tmp_path):
    directory, store = make(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(15)"])
    try:
        value = control_snapshot()
        value["control"]["identity"] = runtime_identity(child.pid)
        store.update(value)
        assert observed_status(directory)["state"] == "RUNNING"
        child.terminate()
        child.wait(timeout=3)
        assert observed_status(directory)["state"] == "UNKNOWN_STALE_HEARTBEAT"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)


def test_exact_cli_stop_bypasses_real_locked_sqlite(tmp_path):
    directory, store = replay_runtime(tmp_path)
    (directory / "code-identity").write_text(code_identity())
    child = subprocess.Popen(
        [sys.executable, "-m", "soc_agent.cli", "continuous", "run", str(directory)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        end = time.monotonic() + 8
        while time.monotonic() < end:
            if (directory / "observation.json").exists() and shown(directory).get("control"):
                break
            assert child.poll() is None
            time.sleep(0.05)
        else:
            raise AssertionError("ordinary CLI did not publish control identity")
        with sqlite3.connect(directory / "service.sqlite") as held:
            held.execute("BEGIN EXCLUSIVE")
            started = time.monotonic()
            request_stop(directory)
            assert time.monotonic() - started < 1
            held.rollback()
        assert child.wait(timeout=10) == 0, child.stderr.read().decode()
        assert observed_status(directory)["state"] == "STOPPED"
        with store.database.transaction(write=False) as c:
            assert (
                sum(
                    json.loads(row[0])["code"] == "CONTINUOUS_STOP_REQUEST"
                    for row in c.execute("SELECT payload FROM external_security_audit")
                )
                == 1
            )
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        child.stderr.close()


def test_stop_never_signals_unbound_process(tmp_path, monkeypatch):
    directory, store = make(tmp_path)
    store.update(control_snapshot())
    # A same-UID test process is still not the exact continuous run entrypoint.
    called = []
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda *args: called.append(args))
    with pytest.raises(ValueError, match="STOP_PROCESS_BINDING"):
        request_stop(directory)
    assert not called


@pytest.mark.asyncio
async def test_cpu_pressure_keeps_control_within_existing_lease(tmp_path):
    directory, service = runtime(tmp_path)
    control = asyncio.create_task(service.control())
    script = (
        "import os,time,resource;resource.setrlimit(resource.RLIMIT_CPU,(2,2));"
        "os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});"
        "end=time.monotonic()+1;\nwhile time.monotonic()<end:pass"
    )
    children = [subprocess.Popen([sys.executable, "-c", script]) for _ in range(2)]
    try:
        await asyncio.sleep(0.6)
        value = shown(directory)
        assert time.monotonic() - value["control"]["monotonic"] < 5
        assert not value["control"]["data_stalled"]
    finally:
        for child in children:
            await asyncio.to_thread(child.wait, timeout=3)
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_cleanup_stop_error_does_not_replace_original_failure(tmp_path):
    _, service = runtime(tmp_path)
    service.last_error = "ORIGINAL_FAILURE"

    async def fail():
        raise ValueError("STOP_ACK_UNVERIFIED")

    service.source.request_stop = fail
    service.stop.set()  # The owner requests shutdown after its original failure.
    await asyncio.wait_for(service.control(), 1)
    assert service.last_error == "ORIGINAL_FAILURE"
    assert str(service.control_stop_error) == "STOP_ACK_UNVERIFIED"


@pytest.mark.asyncio
async def test_busy_timeout_preserves_database_and_control(tmp_path):
    from soc_agent.review.persistence.models import StorageError

    directory, service = runtime(tmp_path)
    service.store.queue.database.timeout = (
        0.2  # Shorter fault-injection budget, not production policy.
    )
    control = asyncio.create_task(service.control())
    try:
        with sqlite3.connect(directory / "queue.sqlite") as held:
            held.execute("BEGIN EXCLUSIVE")
            with pytest.raises(StorageError):
                await service.storage(service.store.queue.counts)
            assert time.monotonic() - shown(directory)["control"]["monotonic"] < 5
            held.rollback()
        assert service.store.queue.counts() == {}
    finally:
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_configured_data_poll_interval_cannot_extend_control_lease(tmp_path):
    directory, service = runtime(tmp_path)
    service.config = service.config.model_copy(update={"heartbeat_seconds": 10})
    control = asyncio.create_task(service.control())
    try:
        await asyncio.sleep(1.3)
        assert shown(directory)["control"]["sequence"] >= 2
        assert shown(directory)["control"]["lease_seconds"] == 5
    finally:
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_runtime_writer_failure_retains_error_and_durable_cleanup(tmp_path, monkeypatch):
    directory, store = replay_runtime(tmp_path)
    service = ContinuousRuntime(directory)
    original = service.store.publish_observation
    attempts = 0

    def fail_once(value, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("INJECTED_CONTROL_WRITER_FAILURE")
        original(value, **kwargs)

    monkeypatch.setattr(service.store, "publish_observation", fail_once)
    with pytest.raises(OSError, match="CONTROL_WRITER_FAILURE"):
        await asyncio.wait_for(service.run(), 5)
    final = store.state()
    assert final["last_error"] == "CONTINUOUS_HEARTBEAT_PUBLICATION_FAILED"
    assert final["cleanup"] == "VERIFIED" and final["final_flush"] == "VERIFIED"
    assert final["state"] == "STOPPED" and not final["collection_live"]


@pytest.mark.asyncio
async def test_health_writer_delay_cannot_delay_control_stop(tmp_path, monkeypatch):
    _, service = runtime(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = service.store.publish_observation

    def held(value, **kwargs):
        entered.set()
        release.wait(2)
        original(value, **kwargs)

    monkeypatch.setattr(service.store, "publish_observation", held)
    control = asyncio.create_task(service.control())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        service.stop.set()
        await asyncio.wait_for(service.source.stop_sent.wait(), 0.5)
        assert not service.control_writer.done()
    finally:
        release.set()
        await control


@pytest.mark.asyncio
async def test_tcx_transport_ack_does_not_bypass_ordered_seal_drain():
    import socket

    from tests.unit.continuous.test_tcx_failure_cleanup import NS, POLICY, ack, message

    from soc_agent.continuous.tcx_producer import TCXProducer

    owner, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    owner.setblocking(False)
    peer.setblocking(False)
    source = TCXProducer(SimpleNamespace(queue_capacity=32, input_sha256="b" * 64))
    source.socket = owner
    loop = asyncio.get_running_loop()
    stream = source.messages(loop, POLICY)

    async def send(raw):
        await loop.sock_sendall(peer, json.dumps(raw).encode())

    try:
        await send(message(0))
        first = await anext(stream)
        list(source.records(first, POLICY))
        await send(message(1, sealed=True))
        next_epoch = message(2)
        next_epoch["generation"] = 8
        await send(next_epoch)
        async with asyncio.timeout(2):
            while source.receiver_generation != 8:
                await asyncio.sleep(0.01)
        pending = asyncio.create_task(source.request_control_stop())
        command = json.loads(await loop.sock_recv(peer, 4096))
        assert command == dict(operation="STOP_CAPTURE", generation=8, policy_sha256="b" * 64)
        await send(ack(generation=8))
        await asyncio.wait_for(pending, 2)
        assert source.transport_stop_ack.is_set()
        assert not source.stop_ack.is_set() and source.remote_cleanup == "UNKNOWN"
        assert source.cleanup_evidence["transport_ack"]["admission"].startswith("PENDING_ORDERED")
        assert source.epoch == 7  # Projection is intentionally paused behind the queued seal.
        for raw in [raw async for raw in stream]:
            list(source.records(raw, POLICY))
        assert source.stop_ack.is_set() and source.remote_cleanup == "VERIFIED"
        assert source.cleanup_evidence["ack"]["namespace"] == NS
    finally:
        await stream.aclose()
        await source.close()
        peer.close()


@pytest.mark.asyncio
async def test_stop_during_async_initialization_is_not_lost(tmp_path, monkeypatch):
    from soc_agent.continuous.investigation_store import InvestigationTasks

    directory, store = make(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = InvestigationTasks.__init__

    def delayed(self, *args, **kwargs):
        entered.set()
        release.wait(2)
        original(self, *args, **kwargs)

    monkeypatch.setattr(InvestigationTasks, "__init__", delayed)
    service = ContinuousRuntime(directory)
    task = asyncio.create_task(service.run())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        store.control(stop=True)
        release.set()
        await asyncio.wait_for(task, 3)
        assert store.state()["state"] == "STOPPED" and store.state()["cleanup"] == "VERIFIED"
    finally:
        release.set()
        if not task.done():
            service.stop.set()
            await task


@pytest.mark.asyncio
async def test_packet_dns_audit_does_not_block_control(tmp_path, monkeypatch):
    from tests.unit.continuous.test_runtime import window

    directory, store = make(tmp_path)
    service = ContinuousRuntime(directory)
    entered = threading.Event()
    original = service.store.event

    def audit(code, detail):
        if code == "CONTINUOUS_DNS_TRANSACTION":
            entered.set()
            time.sleep(1.2)
        return original(code, detail)

    monkeypatch.setattr(service.store, "event", audit)
    monkeypatch.setattr(service.dns, "observe", lambda *args: ({"origin": "FIXTURE"},))
    control = asyncio.create_task(service.control())
    observing = asyncio.create_task(
        service.observe(
            dict(
                sequence=1,
                id=str(uuid4()),
                kind="packet",
                packet=window().packets[0].model_dump(mode="json"),
            )
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        sequence = shown(directory)["control"]["sequence"]
        await asyncio.sleep(0.5)
        assert not observing.done()
        assert shown(directory)["control"]["sequence"] > sequence
        await observing
    finally:
        service.stop.set()
        await control
        await observing


@pytest.mark.asyncio
async def test_long_observation_with_real_progress_is_not_stalled(tmp_path, monkeypatch):
    _, service = runtime(tmp_path)

    async def steps(raw, *, recovering=False):
        for _ in range(8):
            await service.storage(time.sleep, 0.8)

    monkeypatch.setattr(service, "_observe", steps)
    control = asyncio.create_task(service.control())
    started = time.monotonic()
    try:
        await service.observe({"kind": "FIXTURE_MULTI_STAGE"})
        assert time.monotonic() - started >= 6
        assert not service.stop.is_set() and not control.done()
        assert service.data_progress["advanced_monotonic"] > started + 6
    finally:
        service.stop.set()
        await control


@pytest.mark.asyncio
async def test_storage_wait_and_write_are_separate_progress_stages(tmp_path, monkeypatch):
    _, service = runtime(tmp_path)
    entered = threading.Event()

    def predecessor():
        entered.set()
        time.sleep(3)

    preceding = asyncio.create_task(service.storage(predecessor))
    assert await asyncio.to_thread(entered.wait, 1)

    async def steps(raw, *, recovering=False):
        await service.storage(time.sleep, 3)

    monkeypatch.setattr(service, "_observe", steps)
    control = asyncio.create_task(service.control())
    started = time.monotonic()
    try:
        await service.observe({"kind": "FIXTURE_WAIT_THEN_WRITE"})
        assert time.monotonic() - started >= 5.5
        assert not service.stop.is_set() and not control.done()
    finally:
        service.stop.set()
        await control
        await preceding


@pytest.mark.asyncio
async def test_real_runtime_slow_durable_input_recovers_without_collector_restart(
    tmp_path, monkeypatch
):
    directory, store = replay_runtime(tmp_path)
    service = ContinuousRuntime(directory)
    original = service.store.retain

    def retain(raw):
        time.sleep(6.2)
        return original(raw)

    monkeypatch.setattr(service.store, "retain", retain)
    task = asyncio.create_task(service.run())
    degraded = False
    deadline = time.monotonic() + 12
    try:
        while time.monotonic() < deadline:
            if (directory / "observation.json").exists():
                value = shown(directory)
                assert value["last_error"] is None
                assert not task.done() and not service.stop.is_set()
                if value["state"] == "DEGRADED":
                    degraded = True
                    assert value["control"]["data_stalled"]
                if degraded and value["state"] == "RUNNING" and service.metrics["received"] == 1:
                    break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("slow durable input did not recover")
        assert degraded and service.data_recovery_count == 1
        assert service.metrics["collector_restarts"] == service.metrics["source_gaps"] == 0
    finally:
        service.stop.set()
        await asyncio.wait_for(task, 3)
    final = store.state()
    assert final["state"] == "STOPPED" and final["cleanup"] == "VERIFIED"
    assert final["last_error"] is None
    assert service.data_stall_evidence["storage"]["operation"] == "retain"


@pytest.mark.asyncio
async def test_dns_control_status_survives_six_second_durable_storage_stall(tmp_path):
    directory, service = runtime(tmp_path)
    entered, release = threading.Event(), threading.Event()
    reads = []

    class DNSStatus:
        last_error = None

        @property
        def snapshot(self):
            reads.append(time.monotonic())
            return dict(state="RUNNING", cleanup="NOT_STARTED", origin="FIXTURE")

    service.dns_source = DNSStatus()
    await service.observed_snapshot()
    control = asyncio.create_task(service.control())

    def stalled_write():
        entered.set()
        assert release.wait(10)

    writing = asyncio.create_task(service.storage(stalled_write))
    assert await asyncio.to_thread(entered.wait, 1)
    started = time.monotonic()
    degraded = False
    try:
        while time.monotonic() - started < 6.1:
            await asyncio.sleep(0.1)
            value = shown(directory)
            assert value["dns_transport"]["state"] == "RUNNING"
            assert value["dns_transport"]["status_observation_age_seconds"] < 2
            assert time.monotonic() - value["control"]["monotonic"] < 5
            degraded |= value["control"]["data_stalled"]
        assert degraded and len(reads) >= 6
        service.stop.set()
        await asyncio.wait_for(service.source.stop_sent.wait(), 1)
        assert not writing.done()  # STOP does not wait for durable storage.
    finally:
        release.set()
        service.stop.set()
        await writing
        await asyncio.wait_for(control, 2)


@pytest.mark.asyncio
async def test_slow_dns_status_read_does_not_renew_old_observation(tmp_path):
    _, service = runtime(tmp_path)
    entered, release = threading.Event(), threading.Event()

    class DNSStatus:
        @property
        def snapshot(self):
            entered.set()
            assert release.wait(5)
            return dict(state="RUNNING", cleanup="VERIFIED")

    service.dns_source = DNSStatus()
    reading = asyncio.create_task(service.refresh_dns_snapshot())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        await asyncio.sleep(2.1)
        release.set()
        await reading
        value = service.control_dns_snapshot()
        assert value["state"] == "UNKNOWN_STALE_OBSERVATION"
        assert value["cleanup"] == "UNVERIFIED_STATUS_OBSERVATION"
    finally:
        release.set()
        await reading
