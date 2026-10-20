"""File-only metadata fixtures; no capture, sockets, authentication or model loads."""

import json
from uuid import uuid4

import pytest
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.live_stream import Envelope, Stream
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.packet_producer import FlowAssembly, aggregate
from soc_agent.security_ai.collectors.preprocessing import DNSPreprocessing, normalize, progress


@pytest.fixture
def source():
    return Source(session_id=uuid4(), source_digest="a" * 64, origin="ZEEK_NATIVE_LIVE")


@pytest.fixture
def packets(tmp_path):
    path = tmp_path / "input.pcap"
    golden(path)
    return tuple(reference(path))


def feed(source, packets):
    stream = Stream(source)
    stream.accept(Envelope(sequence=1, kind="ready", data={}))
    for i, p in enumerate(packets, 2):
        stream.accept(Envelope(sequence=i, kind="packet", data=p.model_dump(mode="json")))
    return stream


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("tcp", [False, True])
def test_normalization_direction_precision_identity_and_no_payload(tmp_path, source, ipv6, tcp):
    path = tmp_path / "input.pcap"
    golden(path, ipv6=ipv6, tcp=tcp)
    packets = reference(path)
    a = normalize(packets[0], source, 2, packets[0])
    b = normalize(packets[1], source, 3, packets[0])
    assert a.direction == "FIRST_SEEN_FORWARD" and b.direction == "FIRST_SEEN_BACKWARD"
    assert a.flow_key == b.flow_key and a.packet.ns == packets[0].ns
    assert a.session_id == str(source.session_id) and a.source_digest == source.source_digest
    assert a.capture_integrity == "UNVERIFIED"
    assert "NATIVE_ACCURACY_UNVERIFIED" in a.timestamp_precision
    assert "payload" not in a.model_dump() and "fqdn" not in a.model_dump()
    assert (
        normalize(
            packets[0], source.model_copy(update={"session_id": uuid4()}), 2, packets[0]
        ).flow_key
        != a.flow_key
    )


@pytest.mark.parametrize(
    "change",
    [
        {"frame_length": 41},
        {"captured_length": 43},
        {"ip_length": 28},
        {"kind": "udp", "tcp_flags": 2},
        {"destination": "::1"},
    ],
)
def test_unsupported_headers_fail_closed(source, packets, change):
    from soc_agent.security_ai.collectors.packet_input import Packet

    with pytest.raises(ValueError):
        p = Packet.model_validate({**packets[0].model_dump(mode="json"), **change})
        normalize(p, source, 2, p)


def test_missing_metadata_never_zero_filled(packets):
    from soc_agent.security_ai.collectors.packet_input import Packet

    data = packets[0].model_dump(mode="json")
    del data["tcp_flags"]
    with pytest.raises(ValueError):
        Packet.model_validate(data)


def test_stream_and_batch_have_identical_windows_features_and_digests(source, packets):
    stream = feed(source, packets)
    stream.accept(Envelope(sequence=6, kind="closed", data={}))
    result = aggregate(packets, str(source.session_id))
    assert stream.finalized == result["flows"]
    assert stream.flows.peak == result["peak_packet_references"]
    assert progress(stream)["normalized_packets"] == 4
    assert progress(stream)["active_flows"] == 0
    assert progress(stream)["finalization_reasons"] == {"IDLE_TIMEOUT": 1, "SHUTDOWN": 1}
    assert len(stream.normalization_digest) == 64
    assert feed(source, packets).normalization_digest == stream.normalization_digest


@pytest.mark.parametrize(
    "scenario,reason", [("idle", "IDLE_TIMEOUT"), ("active", "ACTIVE_TIMEOUT")]
)
@pytest.mark.parametrize("tcp", [False, True])
def test_timeout_windows_preserve_event_time_feature_duration(
    tmp_path, source, scenario, reason, tcp
):
    path = tmp_path / "input.pcap"
    golden(path, scenario=scenario, tcp=tcp)
    stream = feed(source, reference(path))
    assert stream.finalized[0]["close_reason"] == reason
    assert stream.finalized[0]["eligible"]
    assert stream.finalized[0]["values"][0] == (1 if scenario == "idle" else 119)
    assert len(stream.active) == 1  # no wall-clock synthetic timeout


@pytest.mark.parametrize("flags", [1, 4])
def test_tcp_fin_rst_are_features_not_new_model_window_authority(source, packets, flags):
    p = packets[0].model_copy(update={"tcp_flags": flags})
    stream = feed(source, [p])
    assert stream.finalized == [] and len(stream.active) == 1
    stream.accept(Envelope(sequence=3, kind="closed", data={}))
    flow = stream.finalized[0]
    assert flow["close_reason"] == "SHUTDOWN" and not flow["eligible"]
    assert flow["values"][10 if flags == 1 else 11] == 1


def test_duplicate_sequence_and_same_flow_time_reversal_are_rejected(source, packets):
    stream = feed(source, packets[:1])
    with pytest.raises(ValueError, match="PACKET_INTEGRITY"):
        stream.accept(Envelope(sequence=3, kind="packet", data=packets[0].model_dump(mode="json")))
    stream = feed(source, packets[:2])
    p = packets[0].model_copy(update={"sequence": 3})
    with pytest.raises(ValueError, match="TIMESTAMP_REGRESSION"):
        stream.accept(Envelope(sequence=4, kind="packet", data=p.model_dump(mode="json")))


def test_cross_flow_order_is_observed_without_clamping(source, packets):
    p = packets[0].model_copy(update={"sequence": 3, "source_port": 9000})
    stream = feed(source, [*packets[:2], p])
    assert stream.out_of_order == 1 and len(stream.active) == 2
    assert stream.active[p.key].packets[0].ns == p.ns


def test_flow_packet_budget_incomplete_and_finalize_once(source, packets):
    a = FlowAssembly(str(source.session_id))
    for i in range(128):
        a.add(packets[0].model_copy(update={"sequence": i + 1}))
    assert a.finalized[0]["close_reason"] == "PACKET_LIMIT"
    assert not a.finalized[0]["eligible"] and not a.active
    a.finish()
    with pytest.raises(ValueError, match="ALREADY_FINALIZED"):
        a.finish()
    with pytest.raises(ValueError, match="SEQUENCE_INTEGRITY"):
        a.add(packets[0].model_copy(update={"sequence": 129}))


def test_active_flow_memory_bound_is_explicit(source, packets):
    a = FlowAssembly(str(source.session_id))
    for i in range(128):
        a.add(packets[0].model_copy(update={"sequence": i + 1, "source_port": i}))
    with pytest.raises(ValueError, match="STATE_BUDGET"):
        a.add(packets[0].model_copy(update={"sequence": 129, "source_port": 9999}))
    assert len(a.active) == 128


def dns_event(source, **update):
    row = {
        "ts": 1800000000,
        "uid": "dnsfixture",
        "id.orig_h": "192.0.2.1",
        "id.resp_h": "192.0.2.2",
        "id.orig_p": 40000,
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 1,
        "qtype": 1,
        **update,
    }
    return parse_line((json.dumps(row) + "\n").encode(), "dns", source)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize(
    "fields,reason",
    [
        ({}, "MISSING_RESPONSE_METADATA"),
        ({"rcode": 0}, "RESPONSE_WITHOUT_TIMING"),
        ({"rcode": 0, "rtt": 0.01, "TTLs": [60]}, "MATCHED_TRANSACTION"),
    ],
)
def test_dns_normalization_matching_unknowns_and_duplicate(source, protocol, fields, reason):
    state = DNSPreprocessing(source)
    e = dns_event(source, proto=protocol, **fields)
    state.add(e)
    state.add(e)
    value = state.snapshot()
    assert value["records"] == 1 and value["counters"][reason] == 1
    assert value["counters"]["duplicate_records"] == 1
    assert value["query_packets"] is None and value["response_packets"] is None
    assert not value["fqdn_retained"] and value["dns9"] == "BLOCKED"
    assert e.ttl_seconds == ((60,) if "TTLs" in fields else None)


def test_dns_conflict_wrong_source_and_transport_fail_closed(source):
    state = DNSPreprocessing(source)
    e = dns_event(source)
    state.add(e)
    with pytest.raises(ValueError, match="DUPLICATE_CONFLICT"):
        state.add(e.model_copy(update={"response_code": 3}))
    with pytest.raises(ValueError, match="SOURCE_MISMATCH"):
        state.add(
            e.model_copy(update={"source": source.model_copy(update={"session_id": uuid4()})})
        )
    with pytest.raises(ValueError, match="UNSUPPORTED_TRANSPORT"):
        DNSPreprocessing(source).add(dns_event(source, proto="icmp"))


def test_dns_transaction_completion_order_is_not_falsely_packet_order(source):
    state = DNSPreprocessing(source)
    state.add(dns_event(source, ts=1800000001))
    state.add(dns_event(source, ts=1800000000))
    assert state.snapshot()["counters"]["out_of_order_transaction_starts"] == 1
    assert state.snapshot()["records"] == 2
    assert "NOT_QUERY_RESPONSE_PACKET_ORDER" in state.snapshot()["timestamp_scope"]


def test_port53_metadata_is_not_dns_event(source, packets):
    p = packets[0].model_copy(update={"destination_port": 53})
    stream = feed(source, [p])
    assert stream.port53_metadata_packets == 1
    assert progress(stream)["dns"]["records"] == 0


@pytest.mark.parametrize(
    "reason",
    [
        "TCP_FIN",
        "TCP_RST",
        "VERIFIED_WINDOW_END",
        "EVENT_LIMIT",
        "OUTPUT_LIMIT",
        "CAPTURE_GAP",
        "PARSER_UNSUPPORTED",
    ],
)
def test_unapproved_finalization_does_not_change_model_contract(source, packets, reason):
    a = FlowAssembly(str(source.session_id))
    a.add(packets[0])
    with pytest.raises(ValueError, match="UNSUPPORTED_FINALIZATION"):
        a.finish(reason)
    assert len(a.active) == 1 and not a.finalized and not a.closed


def test_dns_state_budget_is_bounded_and_fail_closed(source):
    a = DNSPreprocessing(source)
    a.seen = {str(i): "a" * 64 for i in range(4096)}
    with pytest.raises(ValueError, match="PREPROCESSING_BUDGET"):
        a.add(dns_event(source))
    assert len(a.seen) == 4096


def test_prepared_without_ready_is_unknown_not_zero(source):
    value = progress(Stream(source))
    assert value["state"] == "NOT_OBSERVED"
    assert value["normalized_packets"] is None and value["active_flows"] is None
