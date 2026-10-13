"""Actual package types / actual SOC adapter; predictions are fixture objects, not inference."""

from tests.unit.operational_features.test_reported_network import record as record
from tests.unit.security_ai.external.conftest import case as case

from soc_agent.security_ai.external import ExternalEvidenceAdapter
from soc_agent.security_ai.operational.network_records import validate_reported_flow


def test_input_shape_receipt_cannot_be_evidence_envelope(record, case):
    _, kwargs = case()
    receipt = validate_reported_flow(record, expected_source_digest=record.content_digest)
    adapter = ExternalEvidenceAdapter()
    for payload in (receipt, receipt.model_dump(mode="json")):
        outcome = adapter.adapt(payload, **kwargs)
        assert outcome.validation.status == "INVALID"
        assert outcome.result is None


def test_existing_v2_synthetic_adapter_preserved(case):
    envelope, kwargs = case()
    outcome = ExternalEvidenceAdapter().adapt(envelope, **kwargs)
    assert outcome.validation.status == "VALIDATED_FOR_ADVISORY"
    assert outcome.result is not None


def test_operational_receipt_cannot_enter_synthetic_v2_or_grant_authority(tmp_path, case):
    from tests.unit.operational_features.test_auth_source_store import (
        INCIDENT,
        admit,
        source,
        store,
    )

    from soc_agent.security_ai.operational.provenance import build_receipt

    s = store(tmp_path)
    event = source()
    admit(s, event)
    receipt = build_receipt(s, incident_id=INCIDENT, sources=(event,))
    _, kwargs = case()
    for payload in (receipt, receipt.model_dump(mode="json")):
        result = ExternalEvidenceAdapter().adapt(payload, **kwargs)
        assert result.validation.status == "INVALID"
        assert result.result is None
