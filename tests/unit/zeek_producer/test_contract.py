import json
from uuid import UUID

import pytest
from tests.zeek_producer_support import golden, valid_wire, write_pcap

from soc_agent.security_ai.collectors.packet_input import Packet, reference, verify_packets
from soc_agent.security_ai.collectors.packet_producer import aggregate


def packet(seq=1, ns=1800000000000000000, **updates):
    sec, frac = divmod(ns, 10**9)
    value = dict(
        sequence=seq,
        seconds=sec,
        microseconds=frac // 1000,
        frame_length=54,
        captured_length=54,
        kind="tcp",
        source="192.0.2.1",
        destination="192.0.2.2",
        source_port=1000,
        destination_port=2000,
        ip_length=40,
        tcp_flags=2,
    )
    value.update(updates)
    return Packet(**value)


@pytest.mark.parametrize(
    "scenario,reason,eligible",
    [("idle", "IDLE_TIMEOUT", 1), ("active", "ACTIVE_TIMEOUT", 1), ("short", "SHUTDOWN", 0)],
)
def test_flow_boundaries_and_first_seen_direction(tmp_path, scenario, reason, eligible):
    p = tmp_path / "input.pcap"
    golden(p, scenario)
    packets = tuple(reference(p))
    report = aggregate(packets, str(UUID(int=1)))
    flow = report["flows"][0]
    assert flow["close_reason"] == reason and report["eligible"] == eligible
    assert flow["values"][1:3] == ([2.0, 1.0] if scenario != "active" else [6.0, 1.0])
    assert report["active_final"] == 0 and report["peak_packet_references"] <= 128
    if eligible:
        assert report["flows"][-1]["eligible"] is False


def test_all14_golden_values_and_mixed_packet_order(tmp_path):
    p = tmp_path / "input.pcap"
    golden(p)
    flow = aggregate(tuple(reference(p)), str(UUID(int=1)))["flows"][0]
    assert flow["values"] == [
        1.0,
        2.0,
        1.0,
        120.0,
        60.0,
        40.0,
        80.0,
        60.0,
        16.329931259155273,
        1.0,
        1.0,
        0.0,
        0.5,
        0.5,
    ]
    assert flow["values_digest"]
    same = (packet(), packet(2, 1800000000000000000))
    assert aggregate(same, "s")["flows"][0]["values"][0] == 0
    bad = (packet(), packet(2, 1799999999999000000))
    with pytest.raises(ValueError, match="TIMESTAMP_REGRESSION"):
        aggregate(bad, "s")
    cross = (packet(), packet(2, 1799999999999000000, source_port=1001))
    assert aggregate(cross, "s")["eligible"] == 0


def test_sequence_memory_and_packet_limit():
    with pytest.raises(ValueError, match="SEQUENCE"):
        aggregate((packet(2),), "s")
    rows = tuple(packet(i + 1, source_port=i + 1) for i in range(129))
    with pytest.raises(ValueError, match="STATE_BUDGET"):
        aggregate(rows, "s")
    rows = tuple(packet(i + 1, 1800000000000000000 + i * 1000) for i in range(128))
    result = aggregate(rows, "s")
    assert result["flows"][0]["close_reason"] == "PACKET_LIMIT" and result["eligible"] == 0


def test_no_timestamp_repair_missing_event_and_metadata_mismatch(tmp_path):
    from soc_agent.security_ai.collectors.offline import file_digest

    p = tmp_path / "input.pcap"
    sha = golden(p)
    rows = reference(p)
    log = tmp_path / "packet.log"

    def save(values):
        log.write_text("".join(v.model_dump_json() + "\n" for v in values))
        return file_digest(log)

    assert verify_packets(p, log, sha, save(rows)) == tuple(rows)
    with pytest.raises(ValueError, match="MISSING_EVENT"):
        verify_packets(p, log, sha, save(rows[:-1]))
    altered = list(rows)
    altered[1] = altered[1].model_copy(update={"microseconds": 499999})
    with pytest.raises(ValueError, match="TIMESTAMP_DIFFERENCE"):
        verify_packets(p, log, sha, save(altered))
    altered = list(rows)
    altered[1] = altered[1].model_copy(update={"tcp_flags": 2})
    with pytest.raises(ValueError, match="PARSER_DIFFERENCE"):
        verify_packets(p, log, sha, save(altered))


def test_ns_pcap_and_incomplete_metadata_never_reach_models(tmp_path):
    p = tmp_path / "nano.pcap"
    write_pcap(p, [(1800000000000000001, valid_wire())], nanosecond=True)
    with pytest.raises(ValueError, match="PRECISION"):
        reference(p)
    value = json.loads(packet().model_dump_json())
    del value["ip_length"]
    with pytest.raises(ValueError):
        Packet.model_validate(value)


def test_integer_moments_float32_order_and_extremes_against_ml(tmp_path, monkeypatch):
    import random

    from tests.research_adapter_support import research_paths

    from soc_agent.security_ai.collectors.packet_input import metadata

    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    from ml.verified_producers.network import Packet as MLPacket
    from ml.verified_producers.network_v1_1 import network_features

    rng = random.Random(20261019)
    for count in (1, 2, 3, 17, 127, 128):
        rows = []
        for i in range(count):
            reverse = bool(i % 2)
            length = rng.choice((40, 60, 1500, 65535))
            rows.append(
                packet(
                    i + 1,
                    1800000000000000000 + i * 1000,
                    source="192.0.2.2" if reverse else "192.0.2.1",
                    destination="192.0.2.1" if reverse else "192.0.2.2",
                    source_port=2000 if reverse else 1000,
                    destination_port=1000 if reverse else 2000,
                    ip_length=length,
                    tcp_flags=rng.randint(0, 255),
                )
            )
        # This is arithmetic-only metadata, not wire/capture input.
        rows = tuple(rows)
        flow = aggregate(rows, "s")["flows"][0]
        vector = network_features(
            tuple(MLPacket(**p) for p in metadata(rows, "s", "a" * 64)),
            source_origin="OFFLINE_PCAP",
            source_identity="a" * 64,
        )
        assert tuple(flow["values"]) == vector.values
