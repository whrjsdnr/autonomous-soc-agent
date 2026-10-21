"""Mixed metadata stream, exact accounting and feature exclusion; no capture."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from soc_agent.security_ai.collectors.finalization import Ledger
from soc_agent.security_ai.collectors.live_contract import new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.live_stream import Stream, decode
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_metadata import UnsupportedPacket


def packet(sequence=1, kind="tcp"):
    return dict(
        sequence=sequence,
        seconds=1800000000,
        microseconds=sequence,
        frame_length=54,
        captured_length=54,
        kind=kind,
        source="192.0.2.1",
        destination="198.51.100.2",
        source_port=40000,
        destination_port=53,
        ip_length=40,
        tcp_flags=16 if kind == "tcp" else 0,
    )


def unsupported(sequence=2):
    return dict(
        sequence=sequence,
        seconds=1800000000,
        microseconds=sequence,
        frame_length=70000,
        captured_length=65535,
        kind="UNSUPPORTED",
    )


def stream():
    return Stream(Source(session_id=uuid4(), source_digest="a" * 64, origin="ZEEK_NATIVE_LIVE"))


def record(sequence, kind, data):
    return (json.dumps(dict(sequence=sequence, kind=kind, data=data)) + "\n").encode()


def mixed():
    lines = [
        record(1, "ready", {}),
        record(2, "packet", packet()),
        record(3, "unsupported", unsupported()),
        record(4, "packet", packet(3, "udp")),
    ]
    counters = dict(
        packet_records=3,
        supported_packet_records=2,
        unsupported_packet_records=1,
        network_events=0,
        dns_events=0,
        pkts_recvd=3,
        pkts_dropped=0,
        pkts_link=3,
        bytes_recvd=70108,
    )
    lines.append(record(5, "counter", counters))
    closed = counters | dict(
        stop_reason="ZEEK_DONE",
        messages_before_closed=5,
        bytes_before_closed=sum(map(len, lines)),
        omitted_packet_records=0,
        omitted_events=0,
    )
    lines.append(record(6, "closed", closed))
    return lines


@pytest.mark.parametrize("kind", ["tcp", "udp"])
def test_supported_packet_legacy_wire_retains_original_metadata(kind):
    s = stream()
    s.accept(decode(record(1, "ready", {})))
    e = decode(record(2, "packet", packet(kind=kind)))
    s.accept(e)
    assert e.event_type == "SUPPORTED_PACKET" and s.packet_count == 1
    assert s.active[next(iter(s.active))].packets[0].sequence == 1


def test_mixed_stream_counter_closed_and_no_feature_or_dns_imputation():
    s, ledger = stream(), Ledger()
    for line in mixed():
        e = decode(line)
        ledger.accept(e, line)
        s.accept(e)
    assert s.closed and ledger.closed and s.observation_count == 3
    assert s.packet_count == 2 and s.unsupported_count == 1
    assert s.counter_snapshot.unsupported_packet_records == 1
    assert sum(f["packet_count"] for f in s.finalized) == 2
    assert sorted(p["sequence"] for f in s.finalized for p in f["packets"]) == [1, 3]
    assert s.dns_count == 0 and s.invalid == 0
    assert (
        ledger.diagnostics()["unsupported_packet"] == 1
        and ledger.diagnostics()["invalid_record"] == 0
    )
    assert all(not f["eligible"] for f in s.finalized)


@pytest.mark.parametrize(
    "change",
    [
        dict(captured_length=70001),
        dict(source="192.0.2.1"),
        dict(kind="tcp"),
        dict(payload="forbidden"),
        dict(sequence=0),
    ],
)
def test_malformed_unsupported_still_fails_closed(change):
    s = stream()
    s.accept(decode(record(1, "ready", {})))
    with pytest.raises(ValueError):
        s.accept(decode(record(2, "unsupported", unsupported(1) | change)))
    assert s.invalid == 1 and s.unsupported_count == s.packet_count == 0


@pytest.mark.parametrize("sequence", [1, 3])
def test_duplicate_or_gap_remains_fatal(sequence):
    s = stream()
    s.accept(decode(record(1, "ready", {})))
    with pytest.raises(ValueError):
        s.accept(decode(record(sequence, "unsupported", unsupported(1))))
    assert s.invalid == 1 and s.duplicate + s.sequence_gap == 1


def test_counter_tampering_and_post_counter_data_are_rejected():
    lines = mixed()
    ledger = Ledger()
    for line in lines[:4]:
        ledger.accept(decode(line), line)
    data = decode(lines[4]).data | dict(unsupported_packet_records=0)
    with pytest.raises(ValueError, match="COUNTER_ACCOUNTING"):
        ledger.accept(decode(record(5, "counter", data)), b"x\n")
    ledger.accept(decode(lines[4]), lines[4])
    with pytest.raises(ValueError, match="POST_COUNTER"):
        ledger.accept(decode(record(6, "packet", packet(4))), b"x\n")
    end = decode(lines[5]).data | dict(pkts_recvd=4)
    with pytest.raises(ValueError, match="CLOSED_COUNTER"):
        ledger.accept(decode(record(6, "closed", end)), b"x\n")


def test_historical_native_schema_failure_fields_are_reproduced_without_guessing_input():
    # Counterexample to the old contract, not a reconstruction of the lost Native record.
    with pytest.raises(ValueError) as caught:
        Packet.model_validate(unsupported(1))
    fields = {e["loc"][0] for e in caught.value.errors()}
    assert {
        "frame_length",
        "kind",
        "source",
        "destination",
        "source_port",
        "destination_port",
        "ip_length",
        "tcp_flags",
    } <= fields
    assert UnsupportedPacket.model_validate(unsupported(1)).frame_length == 70000


def test_real_subprocess_mixed_stream_finishes_with_independent_counter(tmp_path, monkeypatch):
    monkeypatch.setattr(OfflineZeek, "environment", lambda self: {})
    content = b"".join(mixed()).decode()
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.docker_argv",
        lambda *a, **k: [sys.executable, "-c", "import sys;sys.stdout.write(sys.argv[1])", content],
    )
    r = StreamProcess(tmp_path, new_plan(), fixture=Path("/offline-file-only.pcap"))
    monkeypatch.setattr(r, "_absent", lambda: True)
    r.run()
    result = json.loads((tmp_path / "exit.json").read_text())
    assert result["closed_observed"] and result["protocol_finalized"] and result["cleanup_verified"]
    assert result["stream_counters"]["supported_packet"] == 2
    assert result["stream_counters"]["unsupported_packet"] == 1
    assert result["stream_counters"]["invalid_record"] == 0
    assert not result["native_capture"] and result["capture_integrity"] == "UNVERIFIED"
