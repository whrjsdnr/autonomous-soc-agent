"""Official package contract tests, not packet extraction or native model inference."""

import json
from datetime import UTC, datetime
from uuid import UUID

import numpy as np
import pytest

from soc_agent._json import canonical_json_object
from soc_agent.external_runtime import CODE_PIN, CONTRACT
from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import SourceFeatureObservation
from soc_agent.security_ai.operational.network_records import (
    NetworkInputReceipt,
    NetworkSourceRejected,
    ReportedNetworkFlow,
    validate_reported_flow,
)


@pytest.fixture
def record():
    binding = reviewed_binding(
        "detection_quality", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    )
    # Explicit synthetic export fixture; not a captured packet or verified CIC producer.
    values = {name: float(i + 1) for i, name in enumerate(binding.feature_identity.ordered_names)}
    return ReportedNetworkFlow(
        event_id=UUID("b053ee28-b448-42a3-9371-10a86fa65348"),
        source=SourceIdentity(namespace="fixture-flow-export", generation="v1", record="row-1"),
        event_time=datetime(2026, 1, 1, tzinfo=UTC),
        reported_collector_id="fixture",
        reported_collector_version="v1",
        reported_extractor_id="unverified-exporter",
        reported_extractor_version="unknown",
        feature_schema_version=binding.feature_identity.schema_version,
        feature_names_digest=binding.feature_identity.ordered_names_digest,
        feature_values_json=canonical_json_object(values),
    )


def changed(record, values):
    return ReportedNetworkFlow.model_validate(
        record.model_dump() | {"feature_values_json": canonical_json_object(values)}
    )


def validate(record):
    return validate_reported_flow(record, expected_source_digest=record.content_digest)


def test_official_order_numeric_shape_not_authority(record):
    receipt = validate(record)
    assert len(receipt.ordered_features) == 40
    assert receipt.ordered_features[0] == "Fwd Act Data Pkts"
    assert receipt.source == record.source and receipt.event_id == record.event_id
    assert receipt.event_time == record.event_time
    assert receipt.validation_status == "VALIDATED_NUMERIC_SHAPE"
    assert receipt.inference_status == "NOT_INFERABLE"
    assert receipt.source_assurance == "REPORTED_EXPORT_UNATTESTED"
    assert receipt.float32_changed_fields == ()
    assert validate(record) == receipt
    assert NetworkInputReceipt.model_validate_json(receipt.model_dump_json()) == receipt


def test_order_changes_neither_source_values_nor_matrix(record):
    values = json.loads(record.feature_values_json)
    reverse = changed(record, dict(reversed(list(values.items()))))
    assert reverse == record
    assert validate(reverse) == validate(record)


def test_float32_rounding_recorded_without_source_change(record):

    values = json.loads(record.feature_values_json)
    values["Fwd IAT Std"] = 1.00000001
    original = changed(record, values)
    receipt = validate(original)
    assert receipt.float32_changed_fields == ("Fwd IAT Std",)
    assert "1.00000001" in original.feature_values_json
    assert receipt.inference_status == "NOT_INFERABLE"
    assert receipt.input_values_digest != validate(record).input_values_digest


@pytest.mark.parametrize("bad", [None, True, "1", [], {}, 1e100])
def test_invalid_numeric_rejected_without_filling(record, bad):

    values = json.loads(record.feature_values_json)
    values["Fwd IAT Std"] = bad
    broken = changed(record, values)
    with pytest.raises(NetworkSourceRejected):
        validate(broken)


@pytest.mark.parametrize("mode", ["missing", "extra", "five_features"])
def test_exact_top40_not_legacy_five(record, mode):

    values = json.loads(record.feature_values_json)
    if mode == "missing":
        values.pop("Fwd IAT Std")
    elif mode == "extra":
        values["classification"] = "attack"
    else:
        values = {
            "duration_us": 1.0,
            "fwd_packets": 1,
            "bwd_packets": 0,
            "fwd_bytes": 10,
            "bwd_bytes": 0,
        }
    with pytest.raises(NetworkSourceRejected, match="FEATURE_NAMES_OR_COUNT"):
        validate(changed(record, values))


def test_zero_duration_not_divided_or_imputed(record):

    values = json.loads(record.feature_values_json)
    values["Flow Duration"] = 0.0
    receipt = validate(changed(record, values))
    assert receipt.inference_status == "NOT_INFERABLE"
    assert not receipt.float32_changed_fields


def test_source_digest_and_feature_mutation_rejected(record):

    with pytest.raises(NetworkSourceRejected, match="SOURCE_DIGEST"):
        validate_reported_flow(record, expected_source_digest="0" * 64)
    values = json.loads(record.feature_values_json)
    values["Fwd IAT Std"] += 1
    with pytest.raises(NetworkSourceRejected, match="SOURCE_DIGEST"):
        validate_reported_flow(
            changed(record, values), expected_source_digest=record.content_digest
        )


def test_schema_digest_mismatch(record):
    broken = record.model_copy(update={"feature_names_digest": "0" * 64})
    with pytest.raises(NetworkSourceRejected, match="FEATURE_IDENTITY"):
        validate(broken)


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_serialization_rejected(record, token):
    with pytest.raises(ValueError):
        ReportedNetworkFlow.model_validate(
            record.model_dump() | {"feature_values_json": '{"x":' + token + "}"}
        )


def test_untrusted_flags_and_model_instructions_rejected(record):
    with pytest.raises(ValueError):
        ReportedNetworkFlow.model_validate(record.model_dump() | {"VALID": True})
    receipt = validate(record)
    with pytest.raises(ValueError):
        NetworkInputReceipt.model_validate(
            receipt.model_dump() | {"inference_status": "VALIDATED_FOR_ADVISORY"}
        )
    with pytest.raises(ValueError):
        SourceFeatureObservation.model_validate(receipt.model_dump())


def test_float32_overflow_does_not_emit_missing(record):

    values = json.loads(record.feature_values_json)
    values["Fwd IAT Std"] = float(np.finfo(np.float32).max) * 2
    with pytest.raises(NetworkSourceRejected, match="FLOAT32_OVERFLOW"):
        validate(changed(record, values))


def test_naive_time_rejected(record):
    with pytest.raises(ValueError):
        ReportedNetworkFlow.model_validate(
            record.model_dump() | {"event_time": datetime(2026, 1, 1)}
        )


def test_same_official_quality_edge_feature_identity(record):
    quality = reviewed_binding(
        "detection_quality", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    )
    edge = reviewed_binding(
        "edge", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    )
    assert quality.feature_identity == edge.feature_identity
    assert validate(record).ordered_features == edge.feature_identity.ordered_names


def test_reported_collector_is_not_source_attestation(record):
    copied = record.model_copy(update={"reported_extractor_id": "trusted-approved-extractor"})
    result = validate(copied)
    assert result.source_assurance == "REPORTED_EXPORT_UNATTESTED"
    assert result.inference_status == "NOT_INFERABLE"


def test_v2_does_not_accept_operational_origin():
    from soc_agent.security_ai.external.models import DerivationProvenance

    with pytest.raises(ValueError):
        DerivationProvenance(
            origin_assurance="verified_operational",
            fixture_digest="1" * 64,
            extractor_id="declared",
            extractor_version="v1",
        )


def test_untyped_json_cannot_impersonate_reported_record(record):
    with pytest.raises(NetworkSourceRejected, match="UNSUPPORTED_SOURCE_RECORD"):
        validate_reported_flow(record.model_dump(), expected_source_digest=record.content_digest)
