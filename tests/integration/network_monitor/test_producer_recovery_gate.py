"""Diagnostic source continuity cannot substitute for the missing training producer."""

import json

import pytest
from pydantic import ValidationError
from tests.integration.network_monitor.test_pipeline import (
    drain,
    monitor,
    observation,
    prepare,
    source_count,
)

from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.models import FlowSummary, model_gates
from soc_agent.security_ai.operational.provenance import (
    OperationalProvenanceReceipt,
    build_receipt,
    verify_receipt,
)
from soc_agent.state.evidence import utc_now


@pytest.fixture
def saved_diagnostic(tmp_path):
    pipeline = monitor(prepare(tmp_path / "runtime")).pipeline
    packet = observation(pipeline)
    event = pipeline.event(packet, "explicit-packet-fixture", 1)
    assert pipeline.packet(packet, "explicit-packet-fixture", 1)
    drain(pipeline)
    pipeline.flush(utc_now(), "SHUTDOWN")
    drain(pipeline)
    source = pipeline._source(event, packet)
    receipt = build_receipt(pipeline.sources, incident_id=pipeline.incident, sources=(source,))
    with pipeline.queue.database.transaction(write=False) as connection:
        rows = connection.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
    flow = pipeline.decode(pipeline.queue._decode(rows[-1]))
    assert isinstance(flow, FlowSummary)
    return pipeline, event, source, receipt, flow


def test_persisted_source_and_restart_never_issue_operational_authority(
    saved_diagnostic, monkeypatch
):
    from soc_agent.security_ai.external import inference

    def forbidden(*args, **kwargs):
        pytest.fail("Diagnostic recovery must not invoke any native model")

    monkeypatch.setattr(inference, "infer", forbidden)
    pipeline, event, source, receipt, flow = saved_diagnostic
    assert (
        verify_receipt(receipt, pipeline.sources, incident_id=pipeline.incident, sources=(source,))
        == receipt
    )
    assert receipt.rule_status == "UNVERIFIED"
    assert receipt.feature is None and receipt.model_result is None
    assert receipt.inference_status == "NOT_INFERABLE"
    assert receipt.write_disposition == "WRITE_DENIED"
    assert flow.incomplete and flow.direction_definition == "FIRST_OBSERVED_NOT_TRAINING_PRODUCER"
    assert not pipeline.queue.enqueue(event)
    before = pipeline.audit.verify_audit()
    restored = monitor(pipeline.audit.directory).pipeline
    restored.recover()
    drain(restored)
    assert restored.queue.counts() == {"DONE": 2} and source_count(restored) == 2
    assert restored.audit.verify_audit() == before
    for gate in model_gates().values():
        assert gate["operational_input"] == "NOT_INFERABLE"
        assert gate["inference"] == gate["finding_promotion"] == "BLOCKED"


@pytest.mark.parametrize(
    "claim",
    [
        {"producer_revision": "claimed-original-revision"},
        {"golden_pair_verified": True},
        {"feature_status": "VERIFIED"},
        {"direction_definition": "TRAINING_PRODUCER"},
    ],
)
def test_diagnostic_flow_rejects_claimed_training_authority(saved_diagnostic, claim):
    flow = saved_diagnostic[-1]
    with pytest.raises(ValidationError):
        FlowSummary.model_validate(flow.model_dump(mode="json") | claim)


def test_wire_dns_without_retained_name_cannot_claim_operational_admission(saved_diagnostic):
    pipeline, event, *_ = saved_diagnostic
    dns = pipeline.dns_event(event)
    assert dns is not None and dns.question.query_name is None
    assert dns.inference_status == "NOT_INFERABLE"
    with pytest.raises(ValidationError):
        type(dns).model_validate(dns.model_dump(mode="json") | {"inference_status": "INFERABLE"})


@pytest.mark.parametrize("model", ["network-quality", "network-edge", "dns"])
def test_even_rehashed_provenance_cannot_attach_a_model_result(saved_diagnostic, model):
    receipt = saved_diagnostic[-2]
    payload = receipt.model_dump(mode="json", exclude={"receipt_digest"})
    payload["model_result"] = {"model_id": model, "producer_parity": "VERIFIED"}
    payload["receipt_digest"] = content_digest_payload(payload)
    with pytest.raises(ValidationError):
        OperationalProvenanceReceipt.model_validate_json(json.dumps(payload))
