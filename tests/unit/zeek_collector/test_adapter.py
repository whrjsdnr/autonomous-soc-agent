import json
from uuid import uuid4

import pytest
from tests.zeek_collector_support import row

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.parity import DNS9, NETWORK14, require_inference


def source():
    return Source(
        session_id=uuid4(), source_digest="a" * 64, origin="SYNTHETIC_ZEEK_JSON", version="9.0.0"
    )


def test_conn_missing_fields_are_not_zero_and_ns_not_float_clamped():
    raw = row(duration=None, orig_pkts=None, resp_ip_bytes=None).replace(
        b"1800000000.125", b"1800000000.000000011"
    )
    e = parse_line(raw, "network", source())
    assert e.event_ns == 1800000000000000011
    assert e.forward_packets is e.backward_ip_bytes is e.duration_seconds is None
    assert e.backward_packets == 1 and e.forward_ip_bytes == 120
    assert e.network14_parity == e.dns9_parity == "BLOCKED"


@pytest.mark.parametrize("proto", ["tcp", "udp"])
@pytest.mark.parametrize("case", ["normal", "no_response", "no_timing", "truncated"])
def test_dns_transaction_metadata_privacy_and_unknowns(proto, case):
    value = json.loads(
        row("dns", proto=proto, query="private.example", answers=["sensitive.example"])
    )
    if case == "no_response":
        value.pop("rtt")
        value.pop("rcode")
    if case == "no_timing":
        value.pop("rtt")
    if case == "truncated":
        value["TC"] = True
    e = parse_line((json.dumps(value) + "\n").encode(), "dns", source())
    assert e.transaction_id == 7 and e.query_type == 1 and e.ttl_seconds == (10, 20)
    assert "private" not in e.model_dump_json() and "sensitive" not in e.model_dump_json()
    if case == "no_response":
        assert (
            e.response_code is e.response_latency_seconds is None
            and e.diagnostic == "MISSING_RESPONSE_METADATA"
        )
    elif case == "no_timing":
        assert e.response_latency_seconds is None and e.diagnostic == "RESPONSE_WITHOUT_TIMING"
    else:
        assert e.diagnostic == "MATCHED_TRANSACTION"


@pytest.mark.parametrize(
    "change",
    [
        {"ts": True},
        {"ts": "1"},
        {"duration": -1},
        {"duration": False},
        {"orig_pkts": False},
        {"id.orig_h": "not-an-ip"},
        {"proto": "http"},
        {"uid": "bad.name"},
    ],
)
def test_invalid_fields_fail_closed_without_exposing_raw(change):
    with pytest.raises(ValueError, match="ZEEK_RECORD_SCHEMA_REJECTED"):
        parse_line(row(**change), "network", source())


def test_bounds_unknown_schema_and_parity_gate():
    for body in [b"{}\n", b"NaN\n", b'{"ts":NaN}\n', b"x" * 16385]:
        with pytest.raises(ValueError):
            parse_line(body, "network", source())
    with pytest.raises(ValueError):
        Source.model_validate({**source().model_dump(), "version": "8.0.0"})
    assert len(NETWORK14) == 14 and len(DNS9) == 9
    assert any(c == "MISSING" for _, c, _ in NETWORK14)
    with pytest.raises(ValueError, match="NO_MODEL_INVOCATION"):
        require_inference()
