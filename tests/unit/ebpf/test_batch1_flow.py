"""Observed termination evidence is separate from capture/AI eligibility."""

import pytest
from tests.unit.tcx_data.test_pipeline import adapter, raw

from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import FlowAssembly
from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint


def packet(seq, ns, *, flags=0, reverse=False, kind="tcp", port=111):
    return Packet(
        sequence=seq,
        seconds=ns // 10**9,
        microseconds=ns % 10**9 // 1000,
        frame_length=54,
        captured_length=54,
        kind=kind,
        source="192.0.2.2" if reverse else "192.0.2.1",
        destination="192.0.2.1" if reverse else "192.0.2.2",
        source_port=443 if reverse else port,
        destination_port=port if reverse else 443,
        ip_length=40,
        tcp_flags=flags,
    )


@pytest.mark.parametrize("flags,termination", [(1, "ONE_FIN_OBSERVED"), (4, "RST_OBSERVED")])
def test_fin_rst_are_recorded_without_inventing_capture_completeness(flags, termination):
    flow = FlowAssembly("s", compact=True, event_watermark=True)
    flow.add(packet(1, 0, flags=2))
    flow.add(packet(2, 1000, flags=flags))
    flow.finish("CAPTURE_STOP")
    out = flow.finalized[0]
    assert out["lifecycle"]["tcp_termination"] == termination
    assert out["lifecycle"]["last_event_ns"] == 1000
    assert out["lifecycle"]["timeout_witness_ns"] is None
    assert not out["eligible"]
    with pytest.raises(ValueError, match="ALREADY_FINALIZED"):
        flow.finish("NORMAL_END")
    assert len(flow.finalized) == 1


def test_bidirectional_fin_evidence_still_not_capture_authority():
    flow = FlowAssembly("s", compact=True)
    flow.add(packet(1, 0, flags=1))
    flow.add(packet(2, 1000, flags=1, reverse=True))
    flow.finish("NORMAL_END")
    lifecycle = flow.finalized[0]["lifecycle"]
    assert lifecycle["bidirectional"] and lifecycle["tcp_termination"] == "BOTH_FIN_OBSERVED"
    assert lifecycle["capture_window"] == "UNVERIFIED"
    assert not flow.finalized[0]["eligible"]


@pytest.mark.parametrize(
    "kind,stamps,reason",
    [
        ("udp", [0, 30_000_000_000], "IDLE_TIMEOUT"),
        ("tcp", list(range(0, 120_000_000_001, 20_000_000_000)), "ACTIVE_TIMEOUT"),
    ],
)
def test_timeouts_have_actual_event_witness_not_fabricated_end(kind, stamps, reason):
    flow = FlowAssembly("s", compact=True, event_watermark=True)
    for n, stamp in enumerate(stamps, 1):
        flow.add(packet(n, stamp, kind=kind))
    out = flow.finalized[0]
    assert out["close_reason"] == reason
    assert out["lifecycle"]["timeout_witness_ns"] == stamps[-1]
    assert out["lifecycle"]["last_event_ns"] == stamps[-2]
    assert not out["lifecycle"]["bidirectional"]
    flow.finish("CAPTURE_STOP")
    assert (
        flow.closed
        and not flow.active
        and sum(x["packet_count"] for x in flow.finalized) == len(stamps)
    )


def test_cpu_observed_intervals_receipt_and_checkpoint_preserve_source(tmp_path):
    c = adapter(tmp_path)
    for n, ns in enumerate([1000, 2000, 31_000_000_000], 1):
        c.ingest(raw(ns, n, proto=17, port=111 if n < 3 else 222), monotonic=n)
        c.drain()
    c.end_metadata_stream("CAPTURE_STOP")
    summary = c._summary()
    interval = summary["cpu_sequence"]["intervals"]["0"]
    assert interval == dict(
        first_attempt=1, last_attempt=3, first_ns=1000, last_ns=31_000_000_000, received=3
    )
    assert summary["candidate_eligibility"][0]["lifecycle"]["timeout_witness_ns"] == 31_000_000_000
    assert all(not r["eligible"] for r in summary["candidate_eligibility"])
    assert decode_checkpoint(encode_checkpoint(summary)) == summary
