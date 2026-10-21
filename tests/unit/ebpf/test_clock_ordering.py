"""Bounded event-time ordering, never Native clock calibration or capture."""

import struct

import pytest
from tests.ebpf_support import parser, plan
from tests.zeek_producer_support import valid_wire

from soc_agent.security_ai.ebpf.clock import ClockContract
from soc_agent.security_ai.ebpf.collector import EBPFCollector


@pytest.fixture
def stream(tmp_path):
    execute = parser(tmp_path)
    p = plan(origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    c = EBPFCollector(tmp_path / "stream", p)
    c.prepare_metadata()
    c.begin_metadata_stream(0, ClockContract(session_id=p.session_id, domain=p.clock))

    def event(delta, cpu=0, sequence=1):
        _, raw = execute(valid_wire(), ns=1_000_000_000 + delta, sequence=sequence)
        raw = bytearray(raw)
        struct.pack_into("<I", raw, 28, cpu)
        return bytes(raw)

    return c, event


def test_multicpu_inversion_preserves_event_time_and_per_cpu_sequence(stream):
    c, event = stream
    for delta, cpu, seq in [(0, 0, 1), (8_000_000, 1, 1), (4_000_000, 0, 2), (20_000_000, 1, 2)]:
        c.ingest(event(delta, cpu, seq), monotonic=1)
        c.drain()
    c.end_metadata_stream("CAPTURE_STOP")
    assert c.accepted == c.received == 4
    assert c.ordering.inversions == 1 and c.ordering.max_delta == 4_000_000
    assert c.ordering.cpu_counts == {0: 2, 1: 2}
    assert c.ordering.examples[0]["timestamp_ns"] == 1_004_000_000
    f = c.flow.finalized[0]
    assert f["packet_count"] == 4 and f["close_reason"] == "CAPTURE_STOP"
    assert f["values"][0] == pytest.approx(0.02)
    assert not f["eligible"] and c.store.verify_audit()


def test_late_event_is_audited_not_clamped_or_accepted(stream):
    c, event = stream
    c.ingest(event(20_000_000), monotonic=1)
    with pytest.raises(ValueError, match="REORDER_LATE_CAPTURE_GAP"):
        c.ingest(event(1_000_000, 1), monotonic=1)
    c.end_metadata_stream("INCOMPLETE")
    assert c.ordering.late == 1 and c.ordering.max_delta == 19_000_000
    assert c.accepted == 0 and c.discarded == 2
    assert c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
    assert c.store.verify_audit()


def test_sequence_gap_still_blocks_before_reordering(stream):
    c, event = stream
    c.ingest(event(0), monotonic=1)
    with pytest.raises(ValueError, match="CPU_SEQUENCE_GAP"):
        c.ingest(event(1, sequence=3), monotonic=1)


def test_dense_burst_fails_at_fixed_32_event_budget(stream):
    c, event = stream
    for i in range(32):
        c.ingest(event(i, sequence=i + 1), monotonic=1)
        c.drain()
    with pytest.raises(ValueError, match="QUEUE_OVERFLOW_CAPTURE_GAP"):
        c.ingest(event(32, sequence=33), monotonic=1)
    assert len(c.queue) == 32 and c.overflow_rejected == 1
