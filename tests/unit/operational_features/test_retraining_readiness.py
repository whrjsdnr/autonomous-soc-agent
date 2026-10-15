"""Prepared experimental producer specifications never issue runtime authority."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.unit.network_capture.test_packets import packet

from soc_agent.security_ai.operational.network_capture.models import model_gates
from soc_agent.security_ai.operational.provenance import OperationalProvenanceReceipt

CONTRACT = (
    Path(__file__).resolve().parents[3] / "docs/linux-soc-v1/verified-producer-contracts.json"
)
CONTRACT_SHA = "c495542a40607a4ce593232337e2b570194ae4f06ad6fcba6c41b7c2c298f855"


def test_offline_contract_is_pinned_and_not_a_model_package():
    assert hashlib.sha256(CONTRACT.read_bytes()).hexdigest() == CONTRACT_SHA
    snapshot = json.loads(CONTRACT.read_text())
    assert snapshot["model_artifact"] is None
    assert snapshot["training_status"] == "BLOCKED_RAW_LABELED_DATA_MISSING"
    assert snapshot["operational_gate"] == "NOT_INFERABLE"
    assert len(snapshot["network"]["feature_names"]) == 14
    assert len(snapshot["dns"]["feature_names"]) == 7
    assert snapshot["network"]["dtype"] == snapshot["dns"]["dtype"] == "float32"
    assert all("NOT_LEGACY_COMPATIBLE" in snapshot[k]["purpose"] for k in ("network", "dns"))


@pytest.mark.parametrize("model", ["network-quality", "network-edge", "dns"])
def test_prepared_contract_does_not_change_independent_model_gates(model):
    gate = model_gates()[model]
    assert gate["operational_input"] == "NOT_INFERABLE"
    assert gate["inference"] == gate["finding_promotion"] == "BLOCKED"
    assert gate["feature_generation"] == "DIAGNOSTIC_ONLY"


def test_parser_metadata_and_dns_digest_do_not_claim_raw_training_input():
    observation = packet()
    assert observation.capture_timestamp_ns is None and observation.timestamp_origin == "FIXTURE"
    assert observation.dns.query_name is None
    assert observation.dns.query_name_digest
    # A name digest cannot provide the FQDN lexical population of the new producer.
    assert observation.ip_length and observation.interface_id
    assert model_gates()["dns"]["inference"] == "BLOCKED"


def test_v3_rejects_experimental_producer_as_execution_authority():
    # An offline specification is not an OperationalProvenanceReceipt.
    spec = json.loads(CONTRACT.read_text())
    with pytest.raises(ValidationError):
        OperationalProvenanceReceipt.model_validate(spec)
