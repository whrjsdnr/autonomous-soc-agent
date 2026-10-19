"""Native-protocol fixtures only. No interface, privileges or model worker is opened."""

import asyncio
import hashlib
import json

import pytest
from tests.unit.zeek_live.test_contract import native_mock
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.finalization import Closed, publish
from soc_agent.security_ai.collectors.integrity_service import summary
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_stream import Envelope
from soc_agent.security_ai.collectors.packet_input import reference


async def completed(tmp_path, monkeypatch, *, legacy=False):
    c = await native_mock(tmp_path, monkeypatch)
    if legacy:
        monkeypatch.setattr(
            "soc_agent.security_ai.collectors.integrity_service.persist",
            lambda c: summary(c.plan, c.stream, c.result),
        )
    p = tmp_path / "fixture.pcap"
    golden(p)
    packets = reference(p)
    rows = [Envelope(sequence=1, kind="ready", data={}).model_dump_json().encode() + b"\n"]
    for packet in packets:
        rows.append(
            Envelope(sequence=len(rows) + 1, kind="packet", data=packet.model_dump(mode="json"))
            .model_dump_json()
            .encode()
            + b"\n"
        )
    end = Closed(
        stop_reason="ZEEK_DONE",
        packet_records=4,
        network_events=0,
        dns_events=0,
        messages_before_closed=len(rows),
        bytes_before_closed=sum(map(len, rows)),
        omitted_events=0,
        omitted_packet_records=0,
        pkts_recvd=4,
        pkts_dropped=0,
        pkts_link=8,
        bytes_recvd=220,
    )
    rows.append(
        Envelope(sequence=len(rows) + 1, kind="closed", data=end.model_dump())
        .model_dump_json()
        .encode()
        + b"\n"
    )
    raw = b"".join(rows)
    publish(
        c.directory / "exit.json",
        dict(
            plan_digest=c.plan.identity,
            stream_sha256=hashlib.sha256(raw).hexdigest(),
            sequence=len(rows),
            exit_code=0,
            cleanup_verified=True,
            container_absent=True,
            protocol_finalized=True,
            closed_detail=end.model_dump(),
            termination_reason="USER_STOP",
            error=None,
        ),
    )
    path = c.directory / "stream.jsonl"
    path.write_bytes(raw)
    path.chmod(0o600)
    await c.start()
    await asyncio.wait_for(c.task, 5)
    assert c.state == "STOPPED", c.last_error
    return c


@pytest.mark.asyncio
async def test_native_zero_drops_no_model_and_retained_metrics_are_reverified(
    tmp_path, monkeypatch
):
    c = await completed(tmp_path, monkeypatch)
    try:
        s = c.snapshot()
        report = s["capture_integrity_evidence"]
        assert report["session"]["process"] == report["session"]["stream"] == "VERIFIED"
        assert report["session"]["counter"]["reported_drops"] == 0
        assert report["session"]["counter"]["kernel_drops_verified"] is None
        assert report["session"]["capture"] == "UNVERIFIED"
        assert s["network"]["capture_drops"] is None
        assert report["ai_decision"]["decision"] == "BLOCKED_CAPTURE_INTEGRITY"
        assert c.producer is None and s["research"]["records"] == []
        assert report["timeout_complete_flows"] == 1
        assert report["feature_metadata_verified"] == 2
        audit = c.store.runtime.verify_audit()
        files = {
            str(p.relative_to(c.directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in c.directory.rglob("*")
            if p.is_file()
        }
        restored = LiveZeekCollector(tmp_path)
        r = await restored.recover()
        assert r["state"] == "STOPPED" and r["closed_status"] == "OBSERVED"
        assert r["packet_budget"]["used"] == 4 and r["network"]["packet_metadata_count"] == 4
        assert r["capture_integrity_evidence"] == report
        assert r["last_verified_process_session"] == str(c.plan.session_id)
        assert restored.store.runtime.verify_audit() == audit
        assert not r["collection_live"] and restored.task is None and restored.producer is None
        after = {
            str(p.relative_to(c.directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in c.directory.rglob("*")
            if p.is_file()
        }
        assert files == after, (
            "Recovery must not append a new Native diagnostic/audit or invoke models"
        )
    finally:
        await c.stop()


@pytest.mark.asyncio
async def test_legacy_projection_no_proof_file_or_audit_rewrite(tmp_path, monkeypatch):
    c = await completed(tmp_path, monkeypatch, legacy=True)
    try:
        assert not (c.directory / "native-integrity.json").exists()
        before = c.store.runtime.verify_audit()
        restored = LiveZeekCollector(tmp_path)
        r = await restored.recover()
        assert r["state"] == "STOPPED" and r["packet_budget"]["used"] == 4
        assert not (c.directory / "native-integrity.json").exists()
        assert restored.store.runtime.verify_audit() == before and restored.producer is None
        assert r["capture_integrity_evidence"]["session"]["capture"] == "UNVERIFIED"
    finally:
        await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["certificate", "stream", "audit"])
async def test_unbound_or_corrupt_proof_never_restores_as_verified(tmp_path, monkeypatch, tamper):
    c = await completed(tmp_path, monkeypatch)
    try:
        if tamper == "certificate":
            p = c.directory / "native-integrity.json"
            v = json.loads(p.read_text())
            v["session"]["capture"] = "VERIFIED"
            p.write_text(json.dumps(v))
        elif tamper == "stream":
            with (c.directory / "stream.jsonl").open("ab") as f:
                f.write(b"{}\n")
        else:
            import sqlite3

            with sqlite3.connect(c.directory / "monitor.sqlite") as db:
                db.execute("UPDATE monitor_audit SET digest=? WHERE sequence=2", ("f" * 64,))
        restored = LiveZeekCollector(tmp_path)
        if tamper == "audit":
            with pytest.raises(ValueError):
                await restored.recover()
        else:
            s = await restored.recover()
            assert s["state"] == "ERROR" and restored.task is None and restored.producer is None
            assert not s["collection_live"]
    finally:
        if tamper != "audit":
            await c.stop()


@pytest.mark.asyncio
async def test_bound_exit_error_precedes_sidecar_without_masking_cause(tmp_path, monkeypatch):
    c = await native_mock(tmp_path, monkeypatch)
    path = c.directory / "stream.jsonl"
    path.write_bytes(b"")
    path.chmod(0o600)
    publish(
        c.directory / "exit.json",
        dict(
            plan_digest=c.plan.identity,
            sequence=0,
            stream_sha256=hashlib.sha256(b"").hexdigest(),
            exit_code=None,
            cleanup_verified=False,
            container_absent=False,
            error="ZEEK_DOCKER_START_FAILED",
        ),
    )
    assert not (c.directory / "launch-failure.json").exists()
    await c.start()
    await asyncio.wait_for(c.task, 3)
    assert c.state == "ERROR" and c.last_error == "ZEEK_DOCKER_START_FAILED"
    assert c.native_integrity["session"]["capture"] == "FAILED"
    snap = c.snapshot()
    assert snap["collector"]["capture_integrity"] == "FAILED"
    assert snap["network"]["capture_integrity"] == "FAILED"
    assert snap["network"]["integrity_state"] == "CAPTURE_INTEGRITY_FAILED"
    assert snap["finalization_state"] == "FAILED"
    assert c.producer is None and snap["research"]["records"] == []
    c.store.verify()
    await c.stop()


@pytest.mark.asyncio
async def test_resource_guard_records_values_and_never_dispatches_model(tmp_path, monkeypatch):
    from pathlib import Path

    from soc_agent.security_ai.collectors.offline import file_digest
    from soc_agent.security_ai.collectors.producer_service import ProducerService

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    pcap = tmp_path / "offline.pcap"
    sha = golden(pcap)
    c = LiveZeekCollector(tmp_path / "collector")
    await c.prepare(pcap=pcap, sha256=sha)
    p = ProducerService(c)
    packet_log = c.directory / "logs/network14_packets.log"
    packet_log.write_bytes(b"fixture: independent packets supplied by mock\n")
    packet_log.chmod(0o600)
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.producer_service.verify_packets",
        lambda *a: tuple(reference(pcap)),
    )

    async def ready():
        return {"status": "READY"}

    monkeypatch.setattr(p.demo, "start", ready)

    async def forbidden(*args):
        raise AssertionError("resource-blocked model must not execute")

    monkeypatch.setattr(p.demo, "dispatch", forbidden)
    original = Path.read_text

    def observed(path, *args, **kwargs):
        if str(path) == "/proc/meminfo":
            return "MemAvailable: 4194304 kB\n"
        if str(path) == "/proc/pressure/memory":
            return "some avg10=1.50 avg60=0.00 avg300=0.00 total=0\n"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", observed)
    try:
        await p.produce(
            dict(
                packet_mode=True,
                packet_policy_sha256=file_digest(
                    Path(__file__).resolve().parents[3]
                    / "src/soc_agent/security_ai/collectors/network14.zeek"
                ),
                log_sha256={"network14_packets.log": file_digest(packet_log)},
            )
        )
        assert p.state == "BLOCKED_MODEL_HEADROOM_NO_AUTO_RETRY" and p.new_inferences == 0
        with c.store.runtime.database.transaction(write=False) as db:
            details = json.loads(
                db.execute(
                    "SELECT payload FROM monitor_audit WHERE "
                    "json_extract(payload,'$.kind')='ZEEK_MODEL_HEADROOM_BLOCKED'"
                ).fetchone()[0]
            )["details"]
        assert details["available_memory_bytes"] == 4 * 1024**3
        assert details["memory_psi_avg10"] == 1.5 and details["automatic_retry"] is False
    finally:
        await c.stop()


@pytest.mark.asyncio
async def test_reused_controller_drops_old_session_memory_before_recovery(tmp_path, monkeypatch):
    c1 = await completed(tmp_path, monkeypatch)
    c2 = await completed(tmp_path, monkeypatch)
    assert c1.plan.session_id != c2.plan.session_id
    c1.stream.packet_count = 999  # A stale in-memory observation, never a persisted packet.
    old = c1.plan.session_id
    result = await c1.recover()
    assert result["session_id"] == str(c2.plan.session_id) and result["session_id"] != str(old)
    assert result["packet_budget"]["used"] == 4
    assert result["capture_integrity_evidence"]["session"]["session_id"] == result["session_id"]
    assert c1.stream is None and c1.producer is None
    await c1.stop()
    await c2.stop()
