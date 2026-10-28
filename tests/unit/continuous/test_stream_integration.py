"""Nonprivileged producer, stored authentication, journal, recovery and archive tests."""

import asyncio
import ctypes
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from tests.unit.continuous.test_runtime import make, window

from soc_agent.continuous.authentication import AuthenticationWindows, normalized, validate_window
from soc_agent.continuous.native.build import build
from soc_agent.continuous.native.policy import validate
from soc_agent.continuous.native.service import run as root_run
from soc_agent.continuous.retention import archive, verify
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.tcx_producer import decode, replay_packet, replay_wire
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.workflow_models import PackageInput

ROOT = Path(__file__).parents[2] / "fixtures/security_ai_packages/authentication_anomaly"
PIN = "aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6"


def packages():
    return (PackageInput(directory=str(ROOT), manifest_sha256=PIN),)


def auth(i, *, seconds=None, result="failure"):
    return dict(
        event=dict(
            event_id=f"event-{i}",
            account_id="pseudonym-account",
            source_identifier="pseudonym-source",
            authentication_result=result,
            event_time=(
                datetime(2026, 1, 1, tzinfo=UTC)
                + timedelta(seconds=i if seconds is None else seconds)
            ).isoformat(),
        ),
        cursor=f"cursor-{i}",
    )


def test_tcx_roundtrip_and_monotonic_not_relabelled():
    original = window().packets[0]
    encoded = replay_wire(original, 1_000_000_000, 5000)
    event = decode(
        encoded,
        namespace="net:[4026532232]",
        session=uuid4(),
        program="a" * 64,
        sequence=5000,
        clock="FIXTURE_PCAP_EVENT_NS",
    )
    rebuilt = replay_packet(event, original.interface_id)
    assert rebuilt.ip_length == original.ip_length
    assert rebuilt.source_address == original.source_address
    assert event.delivery_sequence == 5000  # independent Continuous transport contract
    with pytest.raises(ValueError, match="MONOTONIC"):
        replay_packet(
            event.model_copy(update={"clock": "KERNEL_MONOTONIC_NS"}), original.interface_id
        )
    with pytest.raises(ValueError, match="BOUND"):
        decode(encoded[:-1], namespace="net:[1]", session=uuid4(), program="a" * 64, sequence=1)


def test_native_build_reproducible_and_no_privileged_entry(tmp_path):
    assert build(tmp_path / "one") == build(tmp_path / "two")
    with pytest.raises(ValueError, match="INSTALLATION_REQUIRED"):
        root_run()
    lib = ctypes.CDLL(str(tmp_path / "one/provider.so"))
    lib.continuous_open.restype = ctypes.c_void_p
    lib.continuous_open.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_void_p,
    ]
    assert not lib.continuous_open(b"/not-loaded", 1, 4026532232, None)


def test_diagnostic_receipt_cannot_activate_continuous():
    with pytest.raises((ValueError, KeyError)):
        validate(json.dumps({"purpose": "NATIVE_DIAGNOSTIC"}).encode())


@pytest.mark.asyncio
async def test_witnessed_auth_stream_real_iforest_and_investigation(tmp_path):
    windows = AuthenticationWindows(packages(), origin="FIXTURE")
    for i in range(42):
        cursor, record = normalized(auth(i, result="failure" if i < 40 else "success"), "a" * 64)
        assert cursor == f"cursor-{i}"
        assert not windows.observe(record, source_digest="a" * 64)
    jobs = windows.advance(datetime(2026, 1, 1, 0, 5, tzinfo=UTC), source_digest="a" * 64)
    assert len(jobs) == 1 and validate_window(jobs[0]) == "ELIGIBLE"
    result = await OfflineWorkflow(tmp_path / "result").run(jobs[0])
    assert result.classification == "UNKNOWN_ANOMALY"
    assert len(result.inference) == 1
    assert result.inference[0].prediction == "anomaly"
    assert result.investigation["status"] == "COMPLETED_READ_ONLY"
    assert result.llm_mode == "SCRIPTED" and result.external_provider_calls == 0
    assert verify_result(tmp_path / "result").incident_id == result.incident_id
    assert not windows.advance(datetime(2026, 1, 1, 0, 6, tzinfo=UTC), source_digest="a" * 64)


@pytest.mark.asyncio
async def test_unwitnessed_auth_never_infers(tmp_path):
    windows = AuthenticationWindows(packages(), origin="FIXTURE")
    windows.observe(normalized(auth(1), "a" * 64)[1], source_digest="a" * 64)
    job = windows.close("a" * 64)[0]
    result = await OfflineWorkflow(tmp_path / "result").run(job)
    assert result.eligibility == "INCOMPLETE" and not result.inference


@pytest.mark.asyncio
async def test_ingress_commit_rebuild_and_queue_idempotency(tmp_path):
    path, store = make(tmp_path, authentication_packages=packages())
    runtime = ContinuousRuntime(path)
    raw = dict(sequence=1, id=str(uuid4()), kind="authentication", authentication=auth(1))
    await runtime.observe(raw)
    assert store.retained() == [raw]
    restored = ContinuousRuntime(path)
    await restored.observe(store.retained()[0], recovering=True)
    assert len(restored.auth.records) == 1
    # Same completed job admission is stable despite a new arrival timestamp.
    job = runtime.auth.close(store.config.input_sha256)[0]
    assert store.enqueue(job)
    assert store.enqueue(job) is False
    with store.database.transaction() as c:
        c.execute("UPDATE continuous_checkpoint SET payload='{}'")
    with pytest.raises(ValueError, match="CHECKPOINT_CORRUPT"):
        store.retained()
    await runtime.analysis.close()
    await restored.analysis.close()


def test_archive_integrity_and_quiescence(tmp_path):
    path, store = make(tmp_path)
    with pytest.raises(ValueError, match="QUIESCENCE"):
        archive(path)
    store.update(dict(state="STOPPED", cleanup="VERIFIED"))
    result = archive(path)
    destination = Path(result["path"])
    assert verify(destination)["queue_counts"] == {}
    with (destination / "queue.sqlite").open("ab") as stream:
        stream.write(b"corruption")
    with pytest.raises(ValueError, match="ARCHIVE_CHANGED"):
        verify(destination)


@pytest.mark.asyncio
async def test_disk_full_does_not_publish_cursor(tmp_path, monkeypatch):
    _, store = make(tmp_path)
    from contextlib import contextmanager

    original = store.database.transaction

    @contextmanager
    def failed(*args, **kwargs):
        raise OSError(28, "simulated ENOSPC")
        yield

    raw = dict(sequence=1, id=str(uuid4()), kind="excluded", affects_integrity=False)
    monkeypatch.setattr(store.database, "transaction", failed)
    with pytest.raises(OSError):
        store.retain(raw)
    monkeypatch.setattr(store.database, "transaction", original)
    assert store.retained() == []


def test_native_segment_compaction_and_corruption(tmp_path):
    from soc_agent.continuous.segments import read

    path, store = make(tmp_path, max_seen_events=128)
    original = window().packets[0]
    last = None
    for seq in range(1, 129):
        wire = replay_wire(original, 1_000_000_000 + seq * 1000, seq)
        event = decode(
            wire, namespace="net:[4026532232]", session=uuid4(), program="a" * 64, sequence=seq
        )
        raw = dict(id=str(uuid4()), wire_hex=wire.hex())
        assert store.native_event(raw, event)
        last = (raw, event)
    segments = store.segments()
    assert len(segments) == 1 and segments[0]["records"] == 128
    assert store.native_event(*last) is False
    with store.database.transaction(write=False) as c:
        assert c.execute("SELECT count(*) FROM continuous_native").fetchone()[0] == 0
        row = c.execute("SELECT * FROM continuous_segments").fetchone()
    assert len(read(path, row["pin"], row["raw_pin"])) == 128
    (path / "segments" / (row["pin"] + ".jsonl.gz")).write_bytes(b"partial")
    with pytest.raises(ValueError, match="SEGMENT_CHANGED"):
        store.segments()


@pytest.mark.asyncio
async def test_real_worker_exit_collector_survives_and_reset_resumes(tmp_path, monkeypatch):
    import sys

    from soc_agent.continuous.service import ContinuousRuntime
    from soc_agent.security_ai.workflow_models import CollectorFailureJob

    path, store = make(tmp_path, worker_circuit_failures=1, authentication_packages=packages())

    class Source:
        async def events(self):
            index = 0
            while True:
                index += 1
                yield dict(
                    sequence=index, id=str(uuid4()), kind="excluded", affects_integrity=False
                )
                await asyncio.sleep(0.05)

        async def close(self):
            pass

    original = asyncio.create_subprocess_exec
    calls = 0

    async def once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return await original(sys.executable, "-c", "raise SystemExit(17)", **kwargs)
        return await original(*args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", once)
    runtime = ContinuousRuntime(path, source=Source())
    await runtime.handoff(CollectorFailureJob(kind="collector_error", code="FIXTURE"))
    task = asyncio.create_task(runtime.run())
    try:
        for _ in range(200):
            if runtime.circuit:
                break
            await asyncio.sleep(0.05)
        assert runtime.circuit and runtime.analysis.snapshot()["child_returncode"] == 17
        before = runtime.metrics["received"]
        await asyncio.sleep(0.15)
        assert runtime.metrics["received"] > before
        windows = AuthenticationWindows(packages(), origin="FIXTURE")
        for i in range(42):
            windows.observe(normalized(auth(i), "a" * 64)[1], source_digest="a" * 64)
        for job in windows.advance(datetime(2026, 1, 1, 0, 5, tzinfo=UTC), source_digest="a" * 64):
            await runtime.handoff(job)
        store.control(reset=True)
        for _ in range(400):
            if runtime.metrics["predictions"] == 1:
                break
            await asyncio.sleep(0.05)
        assert runtime.metrics["predictions"] == 1
        assert runtime.metrics["model_errors"] == 1
        assert runtime.store.queue.counts()["POISON"] == 1
        assert runtime.last_results[-1]["domains"] == ["AUTHENTICATION"]
    finally:
        store.control(stop=True)
        await asyncio.wait_for(task, 15)
    assert store.state()["cleanup"] == "VERIFIED"


def test_journal_cursor_backpressure_and_crash_resume(tmp_path):
    from tests.unit.operational_features.test_native_authentication import row

    from soc_agent.continuous.journal_transport import JournalTransport
    from soc_agent.realtime.queue import QueueFull
    from soc_agent.security_ai.operational.native_authentication import project_journal

    items = [project_journal(row(i, i)) for i in range(1, 4)]

    class Reader:
        identity = "stored-journal-fixture:v1"

        def poll(self, cursor, limit):
            start = 0 if cursor is None else items.index(cursor) + 1
            return items[start : start + limit]

    reader = Reader()
    transport = JournalTransport(tmp_path / "transport", reader, capacity=1)
    with pytest.raises(QueueFull):
        transport.poll(limit=3)
    assert transport.queue.cursor(reader.identity) == items[0]
    held, message = transport.claim()
    assert message["cursor"] == items[0].source.record
    # Simulated process loss after claim: queue recovery redelivers same identity.
    transport = JournalTransport(tmp_path / "transport", reader, capacity=1)
    transport.recover()
    again, again_message = transport.claim()
    assert again.event.event_id == held.event.event_id
    assert message == again_message
    transport.acknowledge_retained(again)
    assert transport.poll(limit=1) == 1
    assert transport.queue.cursor(reader.identity) == items[1]


@pytest.mark.asyncio
async def test_tcx_receiver_scope_errors_and_owned_socket_cleanup(tmp_path, monkeypatch):
    """Actual Unix transport; Root peer and installation boundaries explicitly MOCKED."""
    import socket

    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous import tcx_producer as producer

    base = socket.socket
    path = str(tmp_path / "tcx.sock")
    server = base(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(path)
    server.listen(1)
    server.setblocking(False)

    class PeerSocket(base):
        def connect(self, address):
            return super().connect(path)

        def getsockopt(self, level, opt, *args):
            if opt == socket.SO_PEERCRED:
                import struct

                return struct.pack("3i", 123, 0, 0)  # Explicit mocked privilege boundary.
            return super().getsockopt(level, opt, *args)

    import os

    monkeypatch.setattr(
        producer,
        "installed",
        lambda: dict(
            uid=os.getuid(), namespace="net:[4026532232]", files={"continuous.bpf.o": "a" * 64}
        ),
    )
    monkeypatch.setattr(producer.socket, "socket", PeerSocket)
    received = producer.TCXProducer(config(tmp_path))
    loop = asyncio.get_running_loop()

    async def send():
        peer, _ = await loop.sock_accept(server)
        try:
            await loop.sock_sendall(
                peer,
                json.dumps(
                    dict(
                        contract="soc-continuous-tcx:v1",
                        namespace="net:[999]",
                        ifindex=1,
                        program_sha256="a" * 64,
                    )
                ).encode(),
            )
        finally:
            peer.close()

    sender = asyncio.create_task(send())
    try:
        with pytest.raises(ValueError, match="IDENTITY"):
            _ = [record async for record in received.events()]
        assert received.state == "STOPPED"
        assert received.socket is None
    finally:
        await sender
        server.close()


@pytest.mark.asyncio
async def test_native_monotonic_feature_candidate_never_implicitly_infers(tmp_path):
    from soc_agent.continuous.native_windows import NativeWindows
    from soc_agent.security_ai.collectors.parity import NETWORK14

    values = NativeWindows("net:[4026532232]", "synthetic-kernel-epoch")
    output = []
    session = uuid4()
    for i, ns in enumerate((1_000_000_000, 2_000_000_000, 32_000_000_000, 33_000_000_000), 1):
        event = decode(
            replay_wire(window().packets[0], ns, i),
            namespace="net:[4026532232]",
            session=session,
            program="a" * 64,
            sequence=i,
        )
        output.extend(values.add(event))
    assert output and output[0].quality == "UNKNOWN"
    assert output[0].summary["feature_names"] == [name for name, _, _ in NETWORK14]
    assert output[0].summary["candidate_timeout_complete"]
    result = await OfflineWorkflow(tmp_path / "candidate").run(output[0])
    assert result.eligibility == "UNKNOWN" and not result.inference
    assert result.classification == "DATA_QUALITY_FAILURE"
    assert verify_result(tmp_path / "candidate").incident_id == result.incident_id


@pytest.mark.asyncio
async def test_retain_before_seen_crash_rebuild_does_not_double_count(tmp_path):
    path, store = make(tmp_path, authentication_packages=packages())
    raw = dict(sequence=1, id=str(uuid4()), kind="authentication", authentication=auth(1))
    store.retain(raw)  # Crash immediately after raw+checkpoint commit.
    runtime = ContinuousRuntime(path)
    await runtime.observe(store.retained()[0], recovering=True)
    runtime.last_sequence = 0  # Reopened replay transport begins from the pinned source.
    await runtime.observe(raw)
    assert runtime.metrics["authentication_inputs"] == 1
    assert runtime.metrics["duplicates"] == 1
    assert len(runtime.auth.records) == 1
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_storage_failure_still_closes_owned_resources(tmp_path, monkeypatch):
    from soc_agent.review.persistence.models import StorageError

    path, store = make(tmp_path)

    class Source:
        closed = False

        async def events(self):
            await asyncio.sleep(10)
            if False:
                yield None

        async def close(self):
            self.closed = True

    class Analysis:
        closed = False

        def snapshot(self):
            return {}

        async def close(self):
            self.closed = True

    source = Source()
    analysis = Analysis()
    runtime = ContinuousRuntime(path, source=source, analysis=analysis)
    original = runtime.store.state
    calls = 0

    def fail_after_start():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise StorageError("simulated storage failure")
        return original()

    monkeypatch.setattr(runtime.store, "state", fail_after_start)
    with pytest.raises(StorageError):
        await runtime.run()
    assert source.closed and analysis.closed


def test_root_audit_stream_tail_and_partial_failure():
    import hashlib

    from soc_agent.continuous.native.service import audit_tail

    previous = "0" * 64
    lines = []
    for sequence in range(100):
        payload = dict(previous=previous, sequence=sequence)
        previous = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        lines.append(json.dumps(payload | dict(sha256=previous)).encode() + b"\n")
    assert audit_tail(iter(lines)) == previous
    with pytest.raises(ValueError, match="PARTIAL"):
        audit_tail(iter(lines + [b"{"]))
    with pytest.raises(ValueError, match="INTEGRITY"):
        audit_tail(iter(lines[1:]))


@pytest.mark.asyncio
async def test_concurrent_saved_journal_and_primary_dns_real_models(tmp_path):
    import hashlib
    import json

    from tests.integration.test_raw_dns_workflow import job as dns_job
    from tests.integration.test_raw_dns_workflow import message
    from tests.unit.operational_features.test_native_authentication import row

    # Saved journal provenance only; never invoke a Host journal reader.
    saved = tmp_path / "journal.jsonl"
    rows = [
        row(i + 1, i, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")
        for i in range(42)
    ]
    rows.append(row(43, 301))  # Later source event witnesses the earlier closed window.
    saved.write_text("".join(json.dumps(item) + "\n" for item in rows))
    path, store = make(
        tmp_path,
        authentication_packages=packages(),
        journal_replay_file=saved,
        journal_replay_sha256=hashlib.sha256(saved.read_bytes()).hexdigest(),
    )
    runtime = ContinuousRuntime(path)
    await runtime.handoff(dns_job(message(), message(True, at=120)))
    task = asyncio.create_task(runtime.run())
    try:
        for _ in range(500):
            if runtime.metrics["predictions"] == 1 and runtime.metrics["incidents"] >= 2:
                break
            await asyncio.sleep(0.05)
        assert runtime.metrics["predictions"] == 1
        assert len(store.auxiliary()) == 43
        assert any(r["domains"] == ["DNS"] for r in runtime.last_results)
        assert any(r["domains"] == ["AUTHENTICATION"] for r in runtime.last_results)
        assert runtime.auth.records  # Primary EOF did not discard the side producer's next window.
    finally:
        store.control(stop=True)
        await asyncio.wait_for(task, 15)
    assert store.state()["cleanup"] == "VERIFIED"


def test_root_resource_contract_is_required(tmp_path):
    from soc_agent.continuous.native.service import resource_scope

    proc = tmp_path / "proc"
    groups = tmp_path / "groups"
    proc.mkdir()
    groups.mkdir()
    group = groups / "system.slice/soc-continuous-collector.service"
    group.mkdir(parents=True)
    (proc / "status").write_text(f"NoNewPrivs:\t1\nCapEff:\t{((1 << 39) | (1 << 12) | 1):x}\n")
    (proc / "cgroup").write_text("0::/system.slice/soc-continuous-collector.service\n")
    for name, value in (
        ("memory.max", "134217728"),
        ("pids.max", "4"),
        ("cpu.max", "25000 100000"),
    ):
        (group / name).write_text(value)
    resource_scope(proc, groups)
    (group / "memory.max").write_text("max")
    with pytest.raises(ValueError, match="RESOURCE_SCOPE"):
        resource_scope(proc, groups)


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup", ["VERIFIED", "UNVERIFIED"])
async def test_owner_stop_protocol_is_bounded_and_bound(tmp_path, monkeypatch, cleanup):
    """Actual Unix protocol, explicitly mocked installation and Root peer credentials."""
    import os
    import socket
    import struct

    from tests.unit.continuous.test_runtime import config

    from soc_agent.continuous import tcx_producer as producer

    base = socket.socket
    path = str(tmp_path / "owner.sock")
    server = base(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.bind(path)
    server.listen(1)
    server.setblocking(False)

    class PeerSocket(base):
        def connect(self, address):
            return super().connect(path)

        def getsockopt(self, level, opt, *args):
            if opt == socket.SO_PEERCRED:
                return struct.pack("3i", 123, 0, 0)
            return super().getsockopt(level, opt, *args)

    cfg = config(tmp_path)
    monkeypatch.setattr(
        producer,
        "installed",
        lambda: dict(
            uid=os.getuid(), namespace=cfg.namespace, files={"continuous.bpf.o": "a" * 64}
        ),
    )
    monkeypatch.setattr(producer.socket, "socket", PeerSocket)
    source = producer.TCXProducer(cfg)
    loop = asyncio.get_running_loop()

    async def publish():
        peer, _ = await loop.sock_accept(server)
        try:
            await loop.sock_sendall(
                peer,
                json.dumps(
                    dict(
                        contract="soc-continuous-tcx:v1",
                        namespace=cfg.namespace,
                        ifindex=1,
                        program_sha256="a" * 64,
                        generation=1,
                        sequence=1,
                        frames=[],
                        clock=[1000, 2000, 1001],
                        state=dict(state="RUNNING", counters={}),
                    )
                ).encode(),
            )
            control = json.loads(await loop.sock_recv(peer, 256))
            assert control == dict(
                operation="STOP_CAPTURE", generation=1, policy_sha256=cfg.input_sha256
            )
            await loop.sock_sendall(
                peer,
                json.dumps(
                    dict(
                        contract="soc-continuous-tcx-stop:v1",
                        namespace=cfg.namespace,
                        generation=1,
                        policy_sha256=cfg.input_sha256,
                        cleanup=cleanup,
                    )
                ).encode(),
            )
        finally:
            peer.close()

    async def consume():
        return [record async for record in source.events()]

    publisher = asyncio.create_task(publish())
    consumer = asyncio.create_task(consume())
    try:
        for _ in range(100):
            if source.epoch is not None:
                break
            await asyncio.sleep(0.01)
        if cleanup == "UNVERIFIED":
            with pytest.raises(ValueError, match="REMOTE_CLEANUP_UNVERIFIED"):
                await source.request_stop()
        else:
            await source.request_stop()
        assert await asyncio.wait_for(consumer, 2) == []
    finally:
        await publisher
        server.close()
        await source.close()


def test_replay_archive_restore_preserves_cursor_and_pins(tmp_path):
    from soc_agent.continuous.retention import restore
    from soc_agent.continuous.store import Store

    path, store = make(tmp_path)
    (path / "code-identity").write_text("a" * 64)
    raw = dict(sequence=1, id=str(uuid4()), kind="excluded", affects_integrity=False)
    store.retain(raw)
    store.update(dict(state="STOPPED", cleanup="VERIFIED"))
    archived = Path(archive(path)["path"])
    target = tmp_path / "restored"
    result = restore(archived, target)
    assert result["status"] == "RESTORED_NOT_STARTED"
    assert Store(target).retained() == [raw]
    assert (
        target / "code-identity"
    ).read_text() == "a" * 64  # No automatic re-approval of changed code.
    with pytest.raises((ValueError, FileExistsError)):
        restore(archived, target)
