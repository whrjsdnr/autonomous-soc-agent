import json

import pytest
from tests.ebpf_support import parser, plan
from tests.zeek_producer_support import valid_wire

from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.models import Counters


@pytest.fixture
def parse(tmp_path):
    return parser(tmp_path)


async def active(tmp_path, p=None):
    c = EBPFCollector(tmp_path / "session", p or plan())
    await c.prepare()
    c.begin_fixture(0)
    return c


@pytest.mark.asyncio
async def test_native_prepare_start_denied_and_fixture_origin_denied(tmp_path):
    p = plan(origin="EBPF_TC_NATIVE", clock="KERNEL_MONOTONIC_NS")
    c = EBPFCollector(tmp_path / "native", p)
    s = await c.prepare()
    assert s["ebpf"]["metrics"]["kernel_events"] is None
    with pytest.raises(ValueError, match="APPROVAL_REQUIRED"):
        await c.start()
    with pytest.raises(ValueError, match="FIXTURE_SCOPE"):
        c.begin_fixture(0)
    assert c.store.verify_audit()
    await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["scope", "sequence", "timestamp", "precision", "deadline", "queue", "abi"]
)
async def test_fail_closed_paths(tmp_path, parse, failure):
    c = await active(tmp_path)
    rc, raw = parse(valid_wire())
    assert rc == 0
    c.ingest(raw, monotonic=0)
    c.drain()
    _, raw = parse(valid_wire(), sequence=2)
    if failure == "scope":
        raw = (8).to_bytes(8, "little") + raw[8:]
    if failure == "sequence":
        _, raw = parse(valid_wire(), sequence=3)
    if failure == "timestamp":
        _, raw = parse(valid_wire(), ns=1799999999999999000, sequence=2)
    if failure == "precision":
        _, raw = parse(valid_wire(), ns=1800000000000000001, sequence=2)
    if failure == "abi":
        raw = raw[:-1]
    with pytest.raises(ValueError, match="EBPF_"):
        if failure == "queue":
            for i in range(2, 35):
                _, raw = parse(valid_wire(), sequence=i)
                c.ingest(raw, monotonic=0)
        else:
            c.ingest(raw, monotonic=300 if failure == "deadline" else 1)
            c.drain()
    assert c.state == "ERROR" and not c.network_events() and not c.dns_events()
    assert c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
    assert await c.stop() == c.snapshot()


def counter(**change):
    return Counters.model_validate(
        dict(
            generation=7,
            hook="INGRESS",
            cpu=0,
            observed=0,
            emitted=0,
            ring_lost=0,
            unsupported=0,
            malformed=0,
            disabled=0,
            budget=0,
        )
        | change
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["reset", "wrap", "loss", "scope", "accounting", "overflow"])
async def test_counter_provenance_loss_and_overflow(tmp_path, case):
    c = await active(tmp_path)
    c.counters(counter(observed=10, emitted=10))
    with pytest.raises(ValueError):
        if case in {"reset", "wrap"}:
            c.counters(counter(observed=9, emitted=9))
        if case == "loss":
            c.counters(counter(observed=11, emitted=10, ring_lost=1))
        if case == "scope":
            c.counters(counter(generation=8))
        if case == "accounting":
            c.counters(counter(observed=1))
        if case == "overflow":
            c.counters(counter(observed=2**64, emitted=2**64))
    assert c.snapshot()["ebpf"]["capture_integrity"] == "UNVERIFIED"
    assert c.snapshot()["ebpf"]["counter_provenance"].endswith("NOT_ZEEK_HANDLE")


@pytest.mark.asyncio
async def test_audit_atomic_checkpoint_recovery_tamper_no_reinference(tmp_path, parse):
    c = await active(tmp_path)
    _, raw = parse(valid_wire())
    c.ingest(raw, monotonic=0)
    c.drain()
    await c.stop()
    assert not any("packets" in f for f in c.flow.finalized)
    audit = c.store.verify_audit()
    recovered = await EBPFCollector(c.directory, c.plan).recover()
    assert recovered["runtime_audit_integrity"] == audit
    assert recovered["state"] == "RESTORED_NO_REATTACH" and not recovered["collection_live"]
    assert recovered["restored_evidence"]["accepted"] == 1
    assert c.store.verify_audit() == audit
    with c.store.database.transaction() as db:
        row = db.execute("SELECT value FROM ebpf_checkpoint").fetchone()
        v = json.loads(row[0])
        v["accepted"] = 2
        db.execute("UPDATE ebpf_checkpoint SET value=?", (json.dumps(v),))
    with pytest.raises(ValueError, match="BINDING_FAILED"):
        await EBPFCollector(c.directory, c.plan).recover()


@pytest.mark.asyncio
async def test_dns_candidates_are_not_dns_messages_and_no_combined_zeek_counters(tmp_path, parse):
    import struct

    c = await active(tmp_path)
    frame = bytearray(valid_wire(tcp=False))
    frame[36:38] = struct.pack("!H", 53)
    _, raw = parse(bytes(frame))
    c.ingest(raw, monotonic=0)
    c.drain()
    assert c.dns_candidates == 1 and c.dns_events() == []
    assert c.snapshot()["ebpf"]["dns_state"] == "PORT53_CANDIDATE"
    assert c.snapshot()["ebpf"]["correlation"] == "UNKNOWN_NO_SHARED_PACKET_ID"
    await c.stop()


@pytest.mark.asyncio
async def test_disk_and_checkpoint_idempotence_and_processing_clock(tmp_path, parse):
    c = await active(tmp_path)
    for i in range(1, 65):
        _, raw = parse(valid_wire(), sequence=i)
        c.ingest(raw, monotonic=0)
        c.drain()
    before = c.store.verify_audit()
    c.drain()
    assert c.store.verify_audit() == before
    _, raw = parse(valid_wire(), sequence=65)
    with pytest.raises(ValueError, match="PROCESSING_CLOCK"):
        c.ingest(raw, monotonic=float("nan"))
    assert c.state == "ERROR"
    (c.directory / "oversized-fixture").write_bytes(b"0" * (8 * 1024**2))
    with pytest.raises(ValueError, match="DISK_LIMIT"):
        c.checkpoint()


@pytest.mark.asyncio
async def test_fixture_event_limit_is_distinct_from_kernel_observation_budget(tmp_path, parse):
    c = await active(tmp_path)
    # Boundary state without a costly 4096-event mirrored loop.
    c.received = 4096
    _, raw = parse(valid_wire(), sequence=4097)
    with pytest.raises(ValueError, match="EVENT_LIMIT"):
        c.ingest(raw, monotonic=0)
    assert c.state == "ERROR" and not c.network_events()
