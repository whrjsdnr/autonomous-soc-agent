"""Read-only validation of reported Top40 exports, NOT PCAP feature extraction.

A matching schema/digest is insufficient to establish CICFlowMeter calculation parity.
Until the training producer rules are reviewed, this boundary never issues model inputs,
External Context, advisory validation or execution capabilities.
"""

import hashlib
import json
from math import isfinite
from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID

import numpy as np
from pydantic import Field, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.external_runtime import CODE_PIN, CONTRACT
from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import Hash, Snapshot, Text, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp


class NetworkSourceRejected(ValueError):
    """Messages are fixed codes; source payload and identifiers are not printed."""


class ReportedNetworkFlow(Snapshot):
    """Producer claims are retained as claims. The schema supplies no source attestation."""

    contract_version: Literal["soc-reported-network-flow:v1"] = "soc-reported-network-flow:v1"
    event_id: UUID
    source: SourceIdentity
    event_time: UTCTimestamp
    reported_collector_id: Text
    reported_collector_version: Text
    reported_extractor_id: Text
    reported_extractor_version: Text
    feature_schema_version: Text
    feature_names_digest: Hash
    feature_values_json: Annotated[str, Field(min_length=2, max_length=16384)]

    @model_validator(mode="after")
    def canonical_values(self) -> Self:
        if canonical_json_object(self.feature_values_json) != self.feature_values_json:
            raise ValueError("Canonical feature object required")
        return self

    @property
    def content_digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class NetworkInputReceipt(Snapshot):
    contract_version: Literal["soc-network-input-receipt:v1"] = "soc-network-input-receipt:v1"
    event_id: UUID
    source: SourceIdentity
    event_time: UTCTimestamp
    source_content_digest: Hash
    ordered_features: tuple[Text, ...] = Field(min_length=40, max_length=40)
    feature_names_digest: Hash
    input_values_digest: Hash
    float32_matrix_digest: Hash
    float32_changed_fields: tuple[Text, ...]
    validation_status: Literal["VALIDATED_NUMERIC_SHAPE"] = "VALIDATED_NUMERIC_SHAPE"
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    source_assurance: Literal["REPORTED_EXPORT_UNATTESTED"] = "REPORTED_EXPORT_UNATTESTED"
    blockers: tuple[str, ...] = (
        "TRAINING_EXTRACTION_RULES_UNVERIFIED",
        "SOURCE_ORIGIN_UNATTESTED",
        "OPERATIONAL_CONTEXT_CONTRACT_NOT_ACTIVATED",
    )


def validate_reported_flow(
    record: ReportedNetworkFlow, *, expected_source_digest: str
) -> NetworkInputReceipt:
    """Validate exact official shape and report float32 loss without rounding the input.

    expected_source_digest must come from the caller's independently retained record;
    matching it checks content continuity only. No caller-provided VALID flag is accepted.
    """
    if type(record) is not ReportedNetworkFlow:
        raise NetworkSourceRejected("UNSUPPORTED_SOURCE_RECORD")
    from network_security_ai import NetworkSecurityAIConfig, Top40Contract

    record = ReportedNetworkFlow.model_validate(record.model_dump())
    if record.content_digest != expected_source_digest:
        raise NetworkSourceRejected("SOURCE_DIGEST_MISMATCH")
    binding = reviewed_binding(
        "detection_quality", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    )
    contract = Top40Contract(NetworkSecurityAIConfig(artifact_root=Path(".")))
    if (
        contract.names != binding.feature_identity.ordered_names
        or record.feature_schema_version != binding.feature_identity.schema_version
        or record.feature_names_digest != binding.feature_identity.ordered_names_digest
    ):
        raise NetworkSourceRejected("OFFICIAL_FEATURE_IDENTITY_MISMATCH")
    values = json.loads(record.feature_values_json)
    if set(values) != set(contract.names):
        raise NetworkSourceRejected("FEATURE_NAMES_OR_COUNT_MISMATCH")
    # Upstream Top40 accepts strings/nonfinite as missing. Operational intake does not.
    # Preserve the upstream API; stricter local admission never repairs or fills a value.
    maximum = float(np.finfo(np.float32).max)
    try:
        for value in values.values():
            if type(value) not in (int, float):
                raise NetworkSourceRejected("FINITE_NUMERIC_SCALAR_REQUIRED")
            numeric = float(value)
            if not isfinite(numeric):
                raise NetworkSourceRejected("FINITE_NUMERIC_SCALAR_REQUIRED")
            if abs(numeric) > maximum:
                raise NetworkSourceRejected("FLOAT32_OVERFLOW")
    except OverflowError as error:
        raise NetworkSourceRejected("FLOAT32_OVERFLOW") from error
    matrix = contract.matrix(values)
    changed = tuple(
        name for i, name in enumerate(contract.names) if float(matrix[0, i]) != values[name]
    )
    # Little-endian float32 canonical bytes make matrix hashing platform-independent.
    matrix_digest = hashlib.sha256(matrix.astype("<f4").tobytes()).hexdigest()
    return NetworkInputReceipt(
        event_id=record.event_id,
        source=record.source,
        event_time=record.event_time,
        source_content_digest=record.content_digest,
        ordered_features=contract.names,
        feature_names_digest=contract.digest,
        input_values_digest=content_digest_payload(values),
        float32_matrix_digest=matrix_digest,
        float32_changed_fields=changed,
    )
