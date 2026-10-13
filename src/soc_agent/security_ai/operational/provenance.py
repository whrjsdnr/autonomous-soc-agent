"""Versioned intake receipts, not External Context v2 or inference authorization.

Hash continuity and local source association do not attest collector truthfulness.
Only the existing authentication calculation is described; Network/DNS rules stay
unverified and no model result, approval, or runtime capability can be attached.
"""

from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.external.models import Hash, Snapshot, Text, content_digest_payload
from soc_agent.security_ai.features.models import FeatureSchema
from soc_agent.security_ai.operational.source_records import OperationalSource
from soc_agent.security_ai.operational.source_store import (
    AuthenticationSnapshot,
    OperationalSourceStore,
    SourceRejected,
)
from soc_agent.state.evidence import UTCTimestamp


class SourceLink(Snapshot):
    source: SourceIdentity
    event_id: Text
    content_digest: Hash
    collector_id: Text
    collector_version: Text
    event_time: UTCTimestamp


class AuthenticationFeatureLink(Snapshot):
    extractor_name: Literal["authentication_window"] = "authentication_window"
    extractor_version: Literal["1.0.0"] = "1.0.0"
    calculation_reference: Literal[
        "soc_agent.security_ai.authentication.aggregation:AuthenticationWindowExtractor"
    ] = "soc_agent.security_ai.authentication.aggregation:AuthenticationWindowExtractor"
    feature_schema: FeatureSchema
    input_fingerprint: Hash
    window_digest: Hash
    calculated_at: UTCTimestamp


class OperationalProvenanceReceipt(Snapshot):
    contract_version: Literal["soc-operational-provenance:v3"] = "soc-operational-provenance:v3"
    incident_id: UUID
    sources: tuple[SourceLink, ...] = Field(min_length=1, max_length=10000)
    feature: AuthenticationFeatureLink | None = None
    validation_status: Literal["SOURCE_CHAIN_VALIDATED_UNATTESTED"] = (
        "SOURCE_CHAIN_VALIDATED_UNATTESTED"
    )
    source_assurance: Literal["DECLARED_UNATTESTED"] = "DECLARED_UNATTESTED"
    rule_status: Literal["VERIFIED_INTERNAL_AUTH_CALCULATION", "UNVERIFIED"]
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    model_result: None = None
    write_disposition: Literal["WRITE_DENIED"] = "WRITE_DENIED"
    receipt_digest: Hash

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if len({s.content_digest for s in self.sources}) != len(self.sources):
            raise ValueError("Duplicate provenance sources")
        if (self.feature is not None) != (self.rule_status == "VERIFIED_INTERNAL_AUTH_CALCULATION"):
            raise ValueError("Calculation status does not match feature chain")
        if (
            content_digest_payload(self.model_dump(mode="json", exclude={"receipt_digest"}))
            != self.receipt_digest
        ):
            raise ValueError("Operational receipt integrity rejected")
        return self


def build_receipt(
    store: OperationalSourceStore,
    *,
    incident_id: UUID,
    sources: tuple[OperationalSource, ...],
    authentication: AuthenticationSnapshot | None = None,
) -> OperationalProvenanceReceipt:
    """Resolve saved sources/derived windows; cannot authorize model or action execution."""
    resolved = tuple(store.load(s, expected_incident=incident_id) for s in sources)
    feature = None
    if authentication is not None:
        if (
            authentication not in store.windows(incident_id)
            or tuple(s.content_digest for s in resolved) != authentication.source_digests
        ):
            raise SourceRejected("PROVENANCE_WINDOW_ASSOCIATION_MISMATCH")
        f = authentication.window.features
        feature = AuthenticationFeatureLink(
            feature_schema=f.feature_schema,
            input_fingerprint=f.input_fingerprint,
            window_digest=content_digest_payload(authentication.model_dump(mode="json")),
            calculated_at=f.created_at,
        )
    links = tuple(
        SourceLink(
            source=s.header.source,
            event_id=s.header.event_id,
            content_digest=s.content_digest,
            collector_id=s.header.collector_id,
            collector_version=s.header.collector_version,
            event_time=s.header.observed_at,
        )
        for s in resolved
    )
    # Building with construct is only intermediate canonical data; validate before return.
    draft = OperationalProvenanceReceipt.model_construct(
        incident_id=incident_id,
        sources=links,
        feature=feature,
        rule_status="VERIFIED_INTERNAL_AUTH_CALCULATION" if feature else "UNVERIFIED",
        receipt_digest="0" * 64,
    )
    payload = draft.model_dump(mode="json", exclude={"receipt_digest"})
    return OperationalProvenanceReceipt.model_validate(
        payload | {"receipt_digest": content_digest_payload(payload)}
    )


def verify_receipt(
    receipt: OperationalProvenanceReceipt,
    store: OperationalSourceStore,
    *,
    incident_id: UUID,
    sources: tuple[OperationalSource, ...],
    authentication: AuthenticationSnapshot | None = None,
) -> OperationalProvenanceReceipt:
    receipt = OperationalProvenanceReceipt.model_validate(receipt.model_dump())
    expected = build_receipt(
        store, incident_id=incident_id, sources=sources, authentication=authentication
    )
    if receipt != expected:
        raise SourceRejected("PROVENANCE_ASSOCIATION_MISMATCH")
    return receipt
