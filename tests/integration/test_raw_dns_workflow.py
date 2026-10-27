"""Synthetic wire fixtures; actual stored-PCAP extraction is recorded separately."""

import json
import struct

import pytest

from soc_agent.security_ai.dns_transactions import transactions
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import DNSWireMessage, RawDNSJob


def wire(response=False, name="Example.test", tid=7, rcode=0, qtype=1):
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return (
        struct.pack("!HHHHHH", tid, 0x8180 | rcode if response else 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", qtype, 1)
    )


def message(response=False, proto="udp", at=100, **kwargs):
    data = wire(response, **kwargs)
    if proto == "tcp":
        data = struct.pack("!H", len(data)) + data
    return DNSWireMessage(
        transport=proto,
        timestamp_ns=at,
        source_address="192.0.2.53" if response else "192.0.2.10",
        destination_address="192.0.2.10" if response else "192.0.2.53",
        source_port=53 if response else 50000,
        destination_port=50000 if response else 53,
        source_reference=digest(dict(response=response, proto=proto, at=at, wire=data.hex())),
        wire_hex=data.hex(),
    )


def job(*messages):
    return RawDNSJob(
        kind="raw_dns",
        origin="FIXTURE",
        source_sha256="a" * 64,
        clock_epoch="synthetic-pcap-clock",
        messages=messages,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("proto", ["udp", "tcp"])
async def test_wire_correlation_preserves_exact_model_gate(tmp_path, proto):
    j = job(message(proto=proto), message(True, proto=proto, at=120, name="example.TEST", rcode=3))
    r = transactions(j)
    assert r["matched_transactions"] == 1
    matched = r["events"][1]
    assert matched["duration_ns"] == 20 and matched["response_code"] == 3
    assert matched["query_reference"] == j.messages[0].source_reference
    assert matched["transaction_identity"] == r["events"][0]["transaction_identity"]
    assert r["dns9_feature_names"] == [
        "FQDN_count",
        "subdomain_length",
        "numeric",
        "entropy",
        "special",
        "labels",
        "labels_max",
        "labels_average",
        "len",
    ]
    w = OfflineWorkflow(tmp_path / "run")
    outcome = await w.run(j)
    assert outcome.eligibility == "INCOMPLETE" and outcome.inference == ()
    assert outcome.classification == "DATA_QUALITY_FAILURE" and outcome.external_provider_calls == 0
    assert verify_result(w.directory) == outcome
    path = w.directory / "dns-transactions.json"
    receipt = json.loads(path.read_bytes())
    receipt["matched_transactions"] = 999
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="DNS_RECEIPT_AUDIT"):
        verify_result(w.directory)


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "duplicate_query",
        "duplicate_response",
        "wrong_tid",
        "wrong_type",
        "invalid",
        "tcp_partial",
    ],
)
def test_ambiguity_and_bad_inputs_never_get_model_admission(case):
    messages = [message()]
    if case == "duplicate_query":
        messages += [message(at=110), message(True, at=120)]
    elif case == "duplicate_response":
        messages += [message(True, at=110), message(True, at=120)]
    elif case == "wrong_tid":
        messages += [message(True, at=110, tid=8)]
    elif case == "wrong_type":
        messages += [message(True, at=110, qtype=28)]
    elif case == "invalid":
        messages = [DNSWireMessage.model_validate(message().model_dump() | dict(wire_hex="0000"))]
    elif case == "tcp_partial":
        messages = [
            DNSWireMessage.model_validate(
                message(proto="tcp").model_dump() | dict(wire_hex="0012abcd")
            )
        ]
    r = transactions(job(*messages))
    assert r["model_inference_executed"] is False and r["eligibility"] != "ELIGIBLE"
    if case == "duplicate_query":
        assert r["matched_transactions"] == 0
        assert any("AMBIGUOUS" in e["status"] for e in r["events"])
    if case in ("missing", "wrong_tid", "wrong_type"):
        assert r["missing_responses"]
    if case == "invalid":
        assert r["eligibility"] == "INVALID"


@pytest.mark.asyncio
async def test_clock_reversal_is_quality_failure_not_model_prediction(tmp_path):
    outcome = await OfflineWorkflow(tmp_path / "run").run(
        job(message(at=120), message(True, at=100))
    )
    assert outcome.eligibility == "INVALID" and outcome.inference == ()
    assert outcome.classification == "DATA_QUALITY_FAILURE"


def test_duplicate_source_reference_rejected():
    m = message()
    with pytest.raises(ValueError, match="DUPLICATE_SOURCE_REFERENCE"):
        job(m, m)
