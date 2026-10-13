"""Reported DNS9 rows linked to declared sources; never a DNS feature extractor."""

import hashlib
import json
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.external_runtime import CODE_PIN, CONTRACT
from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.external.metadata import reviewed_binding
from soc_agent.security_ai.external.models import Hash, Snapshot, Text, content_digest_payload
from soc_agent.security_ai.operational.compare_exports import (
    FeatureDifference,
    _difference,
    _number,
)
from soc_agent.security_ai.operational.source_records import DNSQuerySource
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


class DNSRowRejected(ValueError):
    """Only sanitized codes, never raw query, feature payload or credentials."""


class ReportedDNSFeatures(Snapshot):
    contract_version: Literal["soc-reported-dns-features:v1"] = "soc-reported-dns-features:v1"
    incident_id: UUID
    source: SourceIdentity
    source_event_id: Text
    source_content_digest: Hash
    reported_producer_name: Text
    reported_producer_version: Text
    feature_schema_version: Text
    ordered_features: tuple[Text, ...] = Field(min_length=9, max_length=9)
    feature_names_digest: Hash
    feature_values_json: Annotated[str, Field(min_length=2, max_length=4096)]

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if canonical_json_object(self.feature_values_json) != self.feature_values_json:
            raise ValueError("Canonical DNS feature object required")
        return self

    @property
    def content_digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class DNSRuleStatus(Snapshot):
    name: Text
    definition_status: Literal["DOCUMENTED_SEMANTICS_INCOMPLETE"] = (
        "DOCUMENTED_SEMANTICS_INCOMPLETE"
    )
    calculation_status: Literal["UNVERIFIED"] = "UNVERIFIED"
    producer_status: Literal["UNVERIFIED"] = "UNVERIFIED"
    golden_pair_status: Literal["UNVERIFIED"] = "UNVERIFIED"


class DNSInputReceipt(Snapshot):
    contract_version: Literal["soc-dns-input-receipt:v1"] = "soc-dns-input-receipt:v1"
    incident_id: UUID
    source_content_digest: Hash
    row_content_digest: Hash
    feature_names_digest: Hash
    float32_matrix_digest: Hash
    float32_changed_fields: tuple[Text, ...]
    rules: tuple[DNSRuleStatus, ...] = Field(min_length=9, max_length=9)
    validation_status: Literal["NUMERIC_AND_DECLARED_SOURCE_LINK_ONLY"] = (
        "NUMERIC_AND_DECLARED_SOURCE_LINK_ONLY"
    )
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"
    source_assurance: Literal["DECLARED_UNATTESTED"] = "DECLARED_UNATTESTED"


class DNSRowComparison(Snapshot):
    contract_version: Literal["soc-dns-row-comparison:v1"] = "soc-dns-row-comparison:v1"
    reference: DNSInputReceipt
    candidate: DNSInputReceipt
    features: tuple[FeatureDifference, ...] = Field(min_length=9, max_length=9)
    numerical_status: Literal["PASS", "FAIL"]
    training_parity_status: Literal["INCONCLUSIVE"] = "INCONCLUSIVE"
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"


def validate_reported_dns(
    row: ReportedDNSFeatures,
    *,
    source: DNSQuerySource,
    store: OperationalSourceStore,
    expected_incident: UUID,
    expected_source_digest: str,
    expected_row_digest: str,
) -> DNSInputReceipt:
    if type(row) is not ReportedDNSFeatures or type(source) is not DNSQuerySource:
        raise DNSRowRejected("UNSUPPORTED_DNS_ROW_OR_SOURCE")
    row = ReportedDNSFeatures.model_validate(row.model_dump())
    source = DNSQuerySource.model_validate(source.model_dump())
    if row.content_digest != expected_row_digest or source.content_digest != expected_source_digest:
        raise DNSRowRejected("DNS_CONTENT_DIGEST_MISMATCH")
    if (
        row.incident_id != expected_incident
        or source.header.incident_id != expected_incident
        or row.source != source.header.source
        or row.source_event_id != source.header.event_id
        or row.source_content_digest != expected_source_digest
    ):
        raise DNSRowRejected("DNS_SOURCE_OR_INCIDENT_MISMATCH")
    # Actual secure intake lookup, not a caller-provided VALID/attested flag.
    store.load(source, expected_incident=expected_incident)
    from dns_security_ai import DNSFeatureContract
    from dns_security_ai.errors import DNSInputError

    contract = DNSFeatureContract()
    binding = reviewed_binding(
        "litert", expected_code_identity=CODE_PIN, runtime_contract_digest=CONTRACT
    )
    if (
        tuple(contract.names) != binding.feature_identity.ordered_names
        or row.ordered_features != tuple(contract.names)
        or row.feature_schema_version != contract.schema_version
        or row.feature_names_digest != contract.digest
        or contract.digest != binding.feature_identity.ordered_names_digest
    ):
        raise DNSRowRejected("DNS_OFFICIAL_FEATURE_IDENTITY_MISMATCH")
    values = json.loads(row.feature_values_json)
    if set(values) != set(contract.names) or any(
        type(v) not in (int, float) for v in values.values()
    ):
        raise DNSRowRejected("DNS_NUMERIC_CONTRACT_REJECTED")
    try:
        for value in values.values():
            _number(str(value))
        matrix = contract.matrix(values)
    except (DNSInputError, ValueError, OverflowError) as error:
        raise DNSRowRejected("DNS_NUMERIC_CONTRACT_REJECTED") from error
    return DNSInputReceipt(
        incident_id=expected_incident,
        source_content_digest=source.content_digest,
        row_content_digest=row.content_digest,
        feature_names_digest=contract.digest,
        float32_matrix_digest=hashlib.sha256(matrix.astype("<f4").tobytes()).hexdigest(),
        float32_changed_fields=tuple(
            n for i, n in enumerate(contract.names) if float(matrix[0, i]) != values[n]
        ),
        rules=tuple(DNSRuleStatus(name=n) for n in contract.names),
    )


def compare_dns_rows(
    reference: ReportedDNSFeatures,
    candidate: ReportedDNSFeatures,
    *,
    source: DNSQuerySource,
    store: OperationalSourceStore,
    expected_incident: UUID,
    expected_source_digest: str,
    expected_reference_digest: str,
    expected_candidate_digest: str,
) -> DNSRowComparison:
    receipts = tuple(
        validate_reported_dns(
            row,
            source=source,
            store=store,
            expected_incident=expected_incident,
            expected_source_digest=expected_source_digest,
            expected_row_digest=digest,
        )
        for row, digest in (
            (reference, expected_reference_digest),
            (candidate, expected_candidate_digest),
        )
    )
    a, b = (json.loads(row.feature_values_json) for row in (reference, candidate))
    features = tuple(
        _difference(name, str(a[name]), str(b[name])) for name in reference.ordered_features
    )
    return DNSRowComparison(
        reference=receipts[0],
        candidate=receipts[1],
        features=features,
        numerical_status="PASS"
        if all(f.numeric_equal and f.float32_equal for f in features)
        else "FAIL",
    )
