import asyncio
from pathlib import Path

import pytest
from tests.zeek_producer_support import golden

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_contract import (
    LivePlan,
    bundle,
    docker_argv,
    new_plan,
    verify,
)
from soc_agent.security_ai.collectors.live_process import process_identity, same_process
from soc_agent.security_ai.collectors.live_stream import Envelope, Stream, decode
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.packet_producer import aggregate
from soc_agent.security_ai.research.models import digest


def stream():
    p = new_plan()
    return Stream(
        Source(session_id=p.session_id, source_digest=p.identity, origin="ZEEK_NATIVE_LIVE")
    )


def envelope(n, kind, data=None):
    return Envelope(sequence=n, kind=kind, data=data or {})


def test_native_plan_separate_approval_and_limits():
    p = new_plan()
    assert p.identity != new_plan().identity
    assert p.bundle_digest == digest(bundle())
    assert p.native_inference == "BLOCKED"
    assert p.duration_seconds == 300
    verify(p, p.identity)
    with pytest.raises(ValueError, match="APPROVAL_DIGEST_MISMATCH"):
        verify(p, "a" * 64)
    with pytest.raises(ValueError, match="BUNDLE_CHANGED"):
        bad = p.model_copy(update={"bundle_digest": "0" * 64})
        verify(bad, bad.identity)
    for update in ({"interface": "eth0"}, {"duration_seconds": 301}, {"queue_capacity": 1000}):
        with pytest.raises(ValueError):
            LivePlan.model_validate({**p.model_dump(), **update})


def test_live_docker_contract_never_privileged_or_offline_network():
    a = docker_argv(new_plan(), Path("/safe/policy"))
    assert "--network=host" in a and "--cap-add=NET_RAW" in a
    assert "--cap-drop=ALL" in a and "--privileged" not in a
    assert "NET_ADMIN" not in str(a) and "sudo" not in a
    assert "--read-only" in a and "--security-opt=no-new-privileges" in a
    assert "--memory=512m" in a and "--cpus=1" in a and "--pids-limit=64" in a
    assert "readlink /proc/self/ns/net" in a[-3] and "-i lo" in a[-3]
    assert "-w " not in str(a) and "docker.sock" not in str(a)
    b = docker_argv(new_plan(), Path("/safe/policy"), fixture=Path("/fixture.pcap"))
    assert "--network=none" in b and not any(x.startswith("--cap-add") for x in b)
    assert "-i " not in str(b) and "-r /input/input.pcap" in str(b)


def test_stream_sequence_ready_and_duplicate_rejected():
    s = stream()
    with pytest.raises(ValueError, match="READY_MISSING"):
        s.accept(envelope(1, "closed"))
    s.accept(envelope(1, "ready"))
    for n in (1, 3):
        with pytest.raises(ValueError, match="SEQUENCE_INTEGRITY"):
            s.accept(envelope(n, "closed"))


def test_stream_closed_unknown_is_not_capture_verified():
    s = stream()
    s.accept(envelope(1, "ready"))
    s.accept(envelope(2, "closed", {"pkts_recvd": 0, "pkts_dropped": 0}))
    assert s.closed and s.source.capture_integrity == "UNVERIFIED"
    with pytest.raises(ValueError, match="SEQUENCE_INTEGRITY"):
        s.accept(envelope(3, "ready"))


@pytest.mark.parametrize("drop", [1, 87])
def test_actual_drop_fail_closed(drop):
    s = stream()
    s.accept(envelope(1, "ready"))
    with pytest.raises(ValueError, match="DROPS_DETECTED"):
        s.accept(envelope(2, "closed", {"pkts_dropped": drop}))


@pytest.mark.parametrize(
    "data", [{"query": "PRIVATE"}, {"pkts_dropped": -1}, {"pkts_dropped": True}]
)
def test_invalid_closed_not_promoted(data):
    s = stream()
    s.accept(envelope(1, "ready"))
    with pytest.raises(ValueError, match="COUNTER_SCHEMA"):
        s.accept(envelope(2, "closed", data))


@pytest.mark.parametrize("scenario", ["idle", "active"])
def test_packet_stream_golden_pair_timeout_and_shutdown(tmp_path, scenario):
    path = tmp_path / "input.pcap"
    golden(path, scenario=scenario)
    packets = reference(path)
    s = stream()
    s.accept(envelope(1, "ready"))
    for i, p in enumerate(packets, 2):
        s.accept(envelope(i, "packet", p.model_dump(mode="json")))
    s.accept(envelope(len(packets) + 2, "closed", {"pkts_recvd": len(packets), "pkts_dropped": 0}))
    assert s.finalized == aggregate(tuple(packets), str(s.source.session_id))["flows"]
    assert s.finalized[0]["eligible"] and not s.finalized[1]["eligible"]
    assert s.packet_count == len(packets) and not s.active


def test_same_flow_regression_aborts_not_clamped(tmp_path):
    path = tmp_path / "input.pcap"
    golden(path)
    packets = reference(path)
    s = stream()
    s.accept(envelope(1, "ready"))
    s.accept(envelope(2, "packet", packets[0].model_dump(mode="json")))
    bad = packets[1].model_copy(update={"seconds": packets[0].seconds - 1})
    with pytest.raises(ValueError, match="TIMESTAMP_REGRESSION"):
        s.accept(envelope(3, "packet", bad.model_dump(mode="json")))


def test_dns_metadata_exact_time_no_names():
    s = stream()
    s.accept(envelope(1, "ready"))
    row = dict(
        ts=1800000000,
        uid="C123",
        id=dict(orig_h="192.0.2.1", orig_p=1234, resp_h="192.0.2.2", resp_p=53),
        proto="udp",
        trans_id=4,
        qtype=1,
        rcode=0,
        rtt=0.05,
        TTLs=[60],
        TC=False,
    )
    e = s.accept(envelope(2, "dns", row))
    assert e.diagnostic == "MATCHED_TRANSACTION" and e.response_latency_seconds == 0.05
    assert e.event_ns == 1800000000 * 10**9 and e.dns9_parity == "BLOCKED"
    assert "query" not in e.model_dump()
    with pytest.raises(ValueError, match="PRIVACY_REJECTED"):
        s.accept(envelope(3, "dns", {**row, "query": "PRIVATE"}))


@pytest.mark.parametrize(
    "line", [b"{}", b"x" * 16385 + b"\n", b'{"sequence":1,"kind":"BAD","data":{}}\n']
)
def test_partial_oversized_unknown_record_rejected(line):
    with pytest.raises(ValueError):
        decode(line)


@pytest.mark.asyncio
async def test_native_prepare_watch_and_stop_never_authenticates(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )

    def denied(*args, **kwargs):
        raise AssertionError("NO PRIVILEGE OR CAPTURE")

    monkeypatch.setattr("subprocess.Popen", denied)
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", denied)
    c = LiveZeekCollector(tmp_path)
    snapshot = await c.prepare()
    assert snapshot["state"] == "AUTHENTICATION_REQUIRED"
    assert snapshot["collector_command"] and not snapshot["listener_ready"]
    assert not snapshot["collection_live"] and snapshot["research"]["records"] == []
    old = snapshot["session_id"]
    await c.start()
    with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
        await c.prepare()
    result = await c.stop()
    assert result["state"] == "STOPPED" and not result["collector_command"]
    assert (c.directory / "stop.request").exists()
    assert c.directory.stat().st_mode & 0o777 == 0o700
    snapshot = await c.prepare()
    assert snapshot["session_id"] != old
    await c.stop()


@pytest.mark.asyncio
async def test_backend_live_selection_and_mutual_exclusion(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    b = Backend(GUIConfig(data_directory=tmp_path, collector_type="zeek-live"))
    result = await b.zeek_live_prepare()
    assert result["collector"]["type"] == "zeek-live"
    with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
        await b.total_start("both", True, "legacy")
    await b.collector_stop()
    assert (await b.production_status())["state"] == "STOPPED"
    assert not any("auth" in key for key in b._owners)


def test_process_identity_rejects_pid_reuse():
    import os

    identity = process_identity(os.getpid())
    assert same_process(identity)
    assert not same_process({**identity, "start_ticks": "0"})


async def native_mock(tmp_path, monkeypatch):
    import os

    from soc_agent.security_ai.research.service import write_new

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    c = LiveZeekCollector(tmp_path)
    await c.prepare()
    c._control_event("LAUNCHER_ACCEPTED", dict(launcher=process_identity(os.getpid())))
    c.handoff.accepted = process_identity(os.getpid())
    c.handoff.claimed_at = asyncio.get_running_loop().time()
    write_new(
        c.directory / "process.json",
        dict(
            plan_digest=c.plan.identity,
            generation=str(c.plan.controller_generation),
            image=c.plan.image,
            native_capture=True,
            launcher=process_identity(os.getpid()),
        ),
    )
    return c


@pytest.mark.asyncio
async def test_partial_append_drains_after_exit_and_recovers_no_inference(tmp_path, monkeypatch):
    import json

    from soc_agent.security_ai.collectors.export import export
    from soc_agent.security_ai.collectors.offline import file_digest
    from soc_agent.security_ai.research.service import write_new

    c = await native_mock(tmp_path, monkeypatch)
    raw = b'{"sequence":1,"kind":"ready","data":{}}\n'
    path = c.directory / "stream.jsonl"
    path.write_bytes(raw[:15])
    path.chmod(0o600)
    await c.start()
    await asyncio.sleep(0.1)
    assert not c.stream.ready
    with path.open("ab") as f:
        f.write(raw[15:])
    await asyncio.sleep(0.1)
    assert c.snapshot()["state"] == "ACTIVE"
    assert c.snapshot()["collection_live"]
    with path.open("ab") as f:
        f.write(b'{"sequence":2,"kind":"closed","data":{"pkts_dropped":0}}\n')
    write_new(
        c.directory / "exit.json",
        dict(
            plan_digest=c.plan.identity,
            stream_sha256=file_digest(path),
            sequence=2,
            exit_code=0,
            cleanup_verified=True,
            error=None,
        ),
    )
    await asyncio.wait_for(c.task, 2)
    snapshot = c.snapshot()
    assert snapshot["state"] == "STOPPED" and not snapshot["collection_live"]
    assert c.stream.closed and c.queue_depth == 0 and c.producer is None
    assert snapshot["collector"]["capture_integrity"].startswith("UNVERIFIED")
    assert snapshot["research"]["records"] == []
    export(c, tmp_path / "diagnostics.json", "json")
    assert json.loads((tmp_path / "diagnostics.json").read_text())["inference_receipts"] == []
    fresh = LiveZeekCollector(tmp_path)
    restored = await fresh.recover()
    assert restored["state"] == "STOPPED" and fresh.task is None and fresh.producer is None
    assert restored["runtime_audit_integrity"] == "VERIFIED"
    await fresh.stop()
    await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing_closed", "bad_exit", "wrong_digest", "drop", "gap"])
async def test_capture_failure_all_domains_fail_closed(tmp_path, monkeypatch, failure):
    from soc_agent.security_ai.collectors.offline import file_digest
    from soc_agent.security_ai.research.service import write_new

    c = await native_mock(tmp_path, monkeypatch)
    rows = [envelope(1, "ready")]
    if failure != "missing_closed":
        rows.append(
            envelope(
                3 if failure == "gap" else 2,
                "closed",
                {"pkts_dropped": 87 if failure == "drop" else 0},
            )
        )
    path = c.directory / "stream.jsonl"
    path.write_bytes(b"".join((r.model_dump_json() + "\n").encode() for r in rows))
    path.chmod(0o600)
    write_new(
        c.directory / "exit.json",
        dict(
            plan_digest="0" * 64 if failure == "wrong_digest" else c.plan.identity,
            stream_sha256=file_digest(path),
            sequence=len(rows),
            exit_code=1 if failure == "bad_exit" else 0,
            cleanup_verified=True,
            error=None,
        ),
    )
    await c.start()
    await asyncio.wait_for(c.task, 3)
    snapshot = c.snapshot()
    assert snapshot["state"] == "ERROR" and not snapshot["collection_live"]
    assert snapshot["collectors"]["network"] == snapshot["collectors"]["dns"] == "ERROR"
    assert snapshot["research"]["records"] == [] and c.producer is None
    assert snapshot["last_error"].startswith("ZEEK_")
    assert (c.directory / "stop.request").exists()
    await c.stop()


@pytest.mark.asyncio
async def test_reader_failure_requests_stop_and_preserves_audit(tmp_path, monkeypatch):
    c = await native_mock(tmp_path, monkeypatch)

    def broken(*_):
        raise ValueError("ZEEK_LOG_TRUNCATED")

    monkeypatch.setattr(c, "_poll", broken)
    await c.start()
    await asyncio.wait_for(c.task, 3)
    assert c.state == "ERROR" and c.last_error == "ZEEK_LOG_TRUNCATED"
    assert (c.directory / "stop.request").exists()
    c.store.verify()
    await c.stop()


def test_no_privilege_verification_guard():
    from tests.zeek_live_verification_guard import no_native_process

    for command in (
        ["sudo", "-v"],
        ["docker", "run", "--network=host"],
        ["docker", "run", "--cap-add=NET_RAW"],
    ):
        with pytest.raises(PermissionError):
            no_native_process("subprocess.Popen", (command[0], command, None, None))


@pytest.mark.asyncio
async def test_terminal_auth_cancel_propagates_and_stale_command_rejected(tmp_path, monkeypatch):
    from soc_agent.security_ai.collectors.live_process import main

    c = await native_mock(tmp_path, monkeypatch)
    # Native mock above writes process.json. A real first terminal launch must not have one.
    (c.directory / "process.json").unlink()
    c.handoff.accepted = None

    def denied():
        raise ValueError("TOTAL_AUTH_DENIED_OR_CANCELLED")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", denied)
    with pytest.raises(ValueError, match="AUTH_DENIED_CANCELLED_OR_TIMEOUT"):
        await asyncio.to_thread(main, ["--session", str(c.directory), "--approve", c.plan.identity])
    await c.start()
    await asyncio.wait_for(c.task, 3)
    assert c.state == "ERROR" and c.last_error == "ZEEK_AUTH_DENIED_CANCELLED_OR_TIMEOUT"
    assert not c.snapshot()["collection_live"]
    await c.stop()
    with pytest.raises(ValueError, match="SESSION_STOP_REQUESTED"):
        await asyncio.to_thread(main, ["--session", str(c.directory), "--approve", c.plan.identity])


@pytest.mark.asyncio
async def test_native_source_cannot_enter_offline_model_adapter(tmp_path, monkeypatch):
    from soc_agent.security_ai.collectors.producer_service import ProducerService

    c = await native_mock(tmp_path, monkeypatch)
    producer = ProducerService(c)
    with pytest.raises(ValueError, match="SOURCE_AUTHORIZATION_REQUIRED"):
        await producer.produce({})
    with pytest.raises(ValueError, match="SOURCE_AUTHORIZATION_REQUIRED"):
        producer.request({}, "quality")
    assert producer.new_inferences == 0 and producer.demo.adapter.process is None
    await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("audit_fails", [False, True])
async def test_sqlite_failure_stops_before_audit_and_never_reports_verified(
    tmp_path, monkeypatch, audit_fails
):
    import sqlite3

    c = await native_mock(tmp_path, monkeypatch)

    def broken(*_):
        raise sqlite3.OperationalError("simulated private persistence detail")

    monkeypatch.setattr(c, "_poll", broken)
    if audit_fails:
        monkeypatch.setattr(c.store.runtime, "event", broken)
    await c.start()
    await asyncio.wait_for(c.task, 3)
    assert (c.directory / "stop.request").exists()
    value = c.snapshot()
    assert value["state"] == "ERROR" and not value["collection_live"]
    assert "private" not in value["last_error"]
    assert value["research"]["records"] == []
    if audit_fails:
        assert value["runtime_audit_integrity"] == "UNVERIFIED_ABORT_NOT_PERSISTED"
    await c.stop()
