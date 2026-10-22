"""Metadata/clock fixtures only: no kernel, privilege, payload or model worker."""

import ipaddress
from uuid import uuid4

import pytest
from tests.ebpf_support import plan

from soc_agent.security_ai.ebpf.clock import ClockContract, ClockSample
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.ring import ABI
from soc_agent.security_ai.research.models import digest


def raw(stamp=1_000_000, sequence=1, *, port=12345, generation=7, family=4, proto=6):
    src, dst = ("192.0.2.1", "192.0.2.2") if family == 4 else ("2001:db8::1", "2001:db8::2")
    length = (20 if family == 4 else 40) + (20 if proto == 6 else 8)
    return ABI.pack(
        generation,
        stamp,
        sequence,
        1,
        0,
        length + 14,
        length,
        port,
        443,
        family,
        proto,
        2 if proto == 6 else 0,
        1,
        ipaddress.ip_address(src).packed.ljust(16, b"\0"),
        ipaddress.ip_address(dst).packed.ljust(16, b"\0"),
    )


def adapter(tmp_path):
    p = plan(collector="EBPF_TCX", origin="TCX_STREAM_FIXTURE", clock="KERNEL_MONOTONIC_NS")
    c = EBPFCollector(tmp_path / "adapter", p)
    c.prepare_metadata()
    c.begin_metadata_stream(0, ClockContract(session_id=p.session_id, domain=p.clock))
    return c


@pytest.mark.parametrize("family,proto", [(4, 6), (4, 17), (6, 6), (6, 17)])
def test_exact_ns_watermark_and_no_utc_or_native_promotion(tmp_path, family, proto):
    c = adapter(tmp_path)
    for i, (stamp, port) in enumerate([(1001, 12345), (3002, 12345), (31_000_003_002, 5555)], 1):
        c.ingest(raw(stamp, i, port=port, family=family, proto=proto), monotonic=i)
        c.drain()
    c.drain(final=True)  # Consume the observed tail held by the bounded reorder window.
    first = c.flow.finalized[0]
    assert first["close_reason"] == "IDLE_TIMEOUT" and first["eligible"]
    assert first["values"][0] == pytest.approx(2001 / 1e9)
    assert first["values_digest"] == digest(tuple(first["values"]))
    c.end_metadata_stream("CAPTURE_STOP")
    assert c.flow.finalized[-1]["close_reason"] == "CAPTURE_STOP"
    assert not c.flow.finalized[-1]["eligible"]
    assert c.snapshot()["ebpf"]["clock"]["utc_conversion"] == "NOT_PERFORMED"
    assert c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
    assert "192.0.2." not in str(c._summary()) and not c.network_events()
    assert c.store.verify_audit()


def test_active_boundary_precedes_idle_and_packet_budget_remains_incomplete(tmp_path):
    c = adapter(tmp_path)
    c.ingest(raw(1_000, 1), monotonic=1)
    c.drain()
    c.ingest(raw(120_000_001_000, 2, port=5555), monotonic=2)
    c.drain(final=True)
    assert c.flow.finalized[0]["close_reason"] == "ACTIVE_TIMEOUT"
    for i in range(3, 130):
        c.ingest(raw(120_000_001_000 + i, i, port=5555), monotonic=2 + i / 100)
        c.drain(final=True)
    assert len(c.flow.active[next(iter(c.flow.active))].packets) == 2
    assert len(c.flow.finalized) == 1  # Retention no longer truncates at 128 packets.
    c.end_metadata_stream("PACKET_LIMIT")
    assert c.flow.finalized[-1]["close_reason"] == "PACKET_LIMIT"
    assert c.flow.finalized[-1]["packet_count"] == 128
    assert not c.flow.finalized[-1]["eligible"]


@pytest.mark.parametrize(
    "fault", ["cpu_gap", "cpu_replay", "queue", "clock", "length", "generation"]
)
def test_invalid_stream_never_silently_succeeds(tmp_path, fault):
    c = adapter(tmp_path)
    c.ingest(raw(20_000_000 if fault == "clock" else 1_000_000), monotonic=1)
    c.drain()
    if fault == "cpu_gap":
        # Observation attempts include non-emitted skb. Forward gaps are quality
        # evidence, while duplicates/regressions below remain hard failures.
        c.ingest(raw(sequence=4), monotonic=2)
        c.drain(final=True)
        c.end_metadata_stream("CAPTURE_STOP")
        assert c.attempt_gaps == 2 and c.received == c.accepted == 2
        assert all(
            f["close_reason"] == "INCOMPLETE" and not f["eligible"] for f in c.flow.finalized
        )
        assert c.snapshot()["ebpf"]["native_ai"] == "BLOCKED" and not c.network_events()
        return
    with pytest.raises(ValueError):
        if fault == "queue":
            for i in range(2, 35):
                c.ingest(raw(1_000_000 + i, i), monotonic=2)
        elif fault == "clock":
            c.ingest(raw(1, 2, port=5555), monotonic=2)
            c.drain()
        else:
            c.ingest(
                b"short"
                if fault == "length"
                else raw(
                    sequence=4 if fault == "cpu_gap" else 1 if fault == "cpu_replay" else 2,
                    generation=9 if fault == "generation" else 7,
                ),
                monotonic=2,
            )
    assert c.state == "ERROR" and c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
    assert not c.network_events()


def test_clock_calibration_bounds_identity_and_drift(tmp_path):
    c = adapter(tmp_path)
    samples = tuple(
        ClockSample(before_ns=t, wall_ns=t + 10_005, after_ns=t + 10) for t in (10, 30, 50)
    )
    clock = ClockContract(
        session_id=c.plan.session_id,
        domain=c.plan.clock,
        evidence="FIXTURE_CALIBRATION",
        samples=samples,
    )
    assert clock.offset_interval == (9995, 10005)
    assert clock.snapshot()["native_accuracy"] == "UNVERIFIED"
    with pytest.raises(ValueError, match="DRIFT"):
        ClockContract(
            session_id=c.plan.session_id,
            domain=c.plan.clock,
            evidence="FIXTURE_CALIBRATION",
            samples=(*samples[:2], ClockSample(before_ns=50, wall_ns=99999, after_ns=60)),
        )
    for change in ({"session_id": uuid4()}, {"domain": "FIXTURE_PCAP_EVENT_NS"}):
        fresh = EBPFCollector(tmp_path / str(uuid4()), c.plan)
        fresh.prepare_metadata()
        with pytest.raises(ValueError, match="CLOCK_SESSION_SCOPE"):
            fresh.begin_metadata_stream(
                0, ClockContract.model_validate(clock.model_dump() | change)
            )


def test_compact_dense_window_all14_independent_ml_reference(tmp_path, monkeypatch):
    from tests.research_adapter_support import research_paths

    from soc_agent.security_ai.collectors.packet_input import Packet, metadata

    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    from ml.verified_producers.network import Packet as MLPacket
    from ml.verified_producers.network_v1_1 import network_features

    c = adapter(tmp_path)
    original = []
    for i in range(1, 301):
        fields = list(ABI.unpack(raw(i * 1_000_000, i)))
        fields[5], fields[6], fields[11] = 54 + i % 8, 40 + i % 8, (2, 1, 4, 16)[i % 4]
        c.ingest(ABI.pack(*fields), monotonic=i / 1000)
        c.drain()
        original.append(
            Packet(
                sequence=i,
                seconds=1800000000,
                microseconds=i * 1000,
                frame_length=fields[5],
                captured_length=fields[5],
                kind="tcp",
                source="192.0.2.1",
                destination="192.0.2.2",
                source_port=12345,
                destination_port=443,
                ip_length=fields[6],
                tcp_flags=fields[11],
            )
        )
    assert not c.flow.finalized and len(next(iter(c.flow.active.values())).packets) == 2
    c.ingest(raw(31_000_000_000, 301, port=5555), monotonic=1)
    c.drain(final=True)
    expected = network_features(
        tuple(
            MLPacket(**v)
            for v in metadata(
                tuple(original),
                str(c.plan.session_id),
                "a" * 64,
            )
        ),
        source_origin="OFFLINE_PCAP",
        source_identity="a" * 64,
    )
    value = c.flow.finalized[0]
    assert tuple(value["values"]) == expected.values
    assert value["values_digest"] == digest(expected.values)
    assert value["packet_count"] == 300 and value["close_reason"] == "IDLE_TIMEOUT"
    assert c.flow.peak <= 4 and c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
