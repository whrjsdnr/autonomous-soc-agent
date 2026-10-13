"""External inference receipts are immutable advisory data, never SOC Evidence."""

from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_serializer, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.review.identity import content_digest
from soc_agent.review.models import StateAnchor
from soc_agent.state.evidence import UTCTimestamp

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Text = Annotated[str, Field(min_length=1, max_length=256)]
Profile = Literal["detection_quality", "edge", "litert"]
ObservationType = Literal["network_flow_top40", "dns_stateless_feature_record"]
Status = Literal["PENDING", "VALIDATED_FOR_ADVISORY", "UNLINKED", "INVALID"]


class Snapshot(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", hide_input_in_errors=True, revalidate_instances="always"
    )


class ArtifactFile(Snapshot):
    path: Text
    size_bytes: int = Field(strict=True, gt=0)
    sha256: Hash


class ArtifactIdentity(Snapshot):
    release_version: Literal["security-ai-artifacts-v1"]
    catalog_digest: Hash
    loader_manifest_digest: Hash
    files: tuple[ArtifactFile, ...] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def unique_files(self) -> Self:
        names = tuple(f.path for f in self.files)
        if names != tuple(sorted(set(names))):
            raise ValueError("Artifact inventory must be unique and canonical")
        return self


class FeatureIdentity(Snapshot):
    schema_version: Text
    ordered_names: tuple[Text, ...] = Field(min_length=9, max_length=40)
    ordered_names_digest: Hash
    metadata_digest: Hash
    label_mapping_digest: Hash
    ordered_labels: tuple[Text, ...] = Field(min_length=2, max_length=15)


class TrustedExternalModelBinding(Snapshot):
    binding_id: Literal["network-quality", "network-edge", "dns"]
    source_package: Literal["network-security-ai", "dns-security-ai"]
    package_version: Literal["0.1.0"]
    package_code_identity: Hash
    model_id: Text
    model_version: Text
    profile: Profile
    artifact_identity: ArtifactIdentity
    feature_identity: FeatureIdentity
    runtime_contract_digest: Hash
    limitations: tuple[Text, ...]

    @property
    def binding_digest(self) -> str:
        return content_digest(self)


class SourceEvidenceReference(Snapshot):
    evidence_id: UUID
    content_digest: Hash


class IncidentAssociation(Snapshot):
    incident_id: UUID
    snapshot: StateAnchor
    source_evidence_references: tuple[SourceEvidenceReference, ...] = Field(
        min_length=1, max_length=16
    )

    @model_validator(mode="after")
    def incident_matches(self) -> Self:
        ids = tuple(r.evidence_id for r in self.source_evidence_references)
        if self.incident_id != self.snapshot.incident_id or len(set(ids)) != len(ids):
            raise ValueError("Invalid incident/source association")
        return self


class DerivationProvenance(Snapshot):
    # This increment admits only precomputed synthetic sources, not real collectors.
    origin_assurance: Literal["synthetic_contract_only"]
    fixture_digest: Hash
    extractor_id: Text
    extractor_version: Text


class SourceFeatureObservation(Snapshot):
    contract_version: Literal["soc-external-observation:v2"] = "soc-external-observation:v2"
    source_namespace: Text
    source_event_id: Text
    source_observation_id: Text
    observation_type: ObservationType
    event_time_start: UTCTimestamp | None
    event_time_end: UTCTimestamp | None
    entity_reference: Text | None
    feature_identity: FeatureIdentity
    # Immutable canonical JSON, not a mutable nested dict.
    feature_payload: str
    derivation_provenance: DerivationProvenance
    synthetic: Literal[True]
    association: IncidentAssociation | None = None

    @field_serializer("event_time_start", "event_time_end")
    def serialize_time(self, value: datetime | None) -> str | None:
        return (
            None
            if value is None
            else value.isoformat(timespec="microseconds").replace("+00:00", "Z")
        )

    @model_validator(mode="after")
    def source_shape(self) -> Self:
        if canonical_json_object(self.feature_payload) != self.feature_payload:
            raise ValueError("Noncanonical source features")
        if (self.event_time_start is None) != (self.event_time_end is None):
            raise ValueError("Incomplete source interval")
        if self.event_time_start is not None and self.event_time_start > self.event_time_end:
            raise ValueError("Reversed source interval")
        return self

    def source_payload(self) -> dict[str, JsonValue]:
        """Original source snapshot excluding incident association (avoids circular IDs)."""
        return self.model_dump(mode="json", exclude={"association"})

    @property
    def source_content_digest(self) -> str:
        from hashlib import sha256

        return sha256(canonical_json_object(self.source_payload()).encode("utf-8")).hexdigest()

    @property
    def observation_key(self) -> str:
        from hashlib import sha256

        return sha256(
            canonical_json_object(
                {
                    "namespace": self.source_namespace,
                    "event": self.source_event_id,
                    "observation": self.source_observation_id,
                    "type": self.observation_type,
                    "content": self.source_content_digest,
                }
            ).encode("utf-8")
        ).hexdigest()


class InferenceProvenance(Snapshot):
    """Trusted caller's assertion, not an unsigned producer VALID flag or signature."""

    inference_origin: Literal["LOCAL_MANAGED_INFERENCE"]
    binding_digest: Hash
    observation_digest: Hash
    feature_input_digest: Hash
    artifact_identity: ArtifactIdentity
    execution_environment_digest: Hash


class ValidationReport(Snapshot):
    rule_version: Literal["soc-external-validation:v2"] = "soc-external-validation:v2"
    status: Status
    code: Text
    limitations: tuple[Text, ...] = (
        "Model inference is not observed Evidence, attack confirmation or execution authority.",
        "Caller provenance and hashes do not establish source authenticity or model correctness.",
        "Artifact bytes, inference execution and operational efficacy are not checked here.",
    )


class ExternalModelResultContent(Snapshot):
    contract_version: Literal["soc-external-model-result:v2"] = "soc-external-model-result:v2"
    original_envelope_digest: Hash
    normalized_envelope_digest: Hash
    original_envelope: str
    binding: TrustedExternalModelBinding
    observation: SourceFeatureObservation
    provenance: InferenceProvenance
    inference_time: UTCTimestamp
    received_at: UTCTimestamp
    feature_input_digest: Hash
    semantic_key: Hash
    semantic_output_digest: Hash
    score_semantics: Literal[
        "network_uncalibrated_class_probabilities", "dns_uncalibrated_malicious_probability"
    ]
    validation: ValidationReport

    @field_serializer("inference_time", "received_at")
    def serialize_time(self, value: datetime) -> str:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class ExternalModelResult(ExternalModelResultContent):
    result_digest: Hash

    @model_validator(mode="after")
    def integrity(self) -> Self:
        from hashlib import sha256

        if self.validation.status not in ("VALIDATED_FOR_ADVISORY", "UNLINKED"):
            raise ValueError("Rejected input cannot contain a normalized result")
        if canonical_json_object(self.original_envelope) != self.original_envelope:
            raise ValueError("Noncanonical envelope snapshot")
        if (
            sha256(self.original_envelope.encode("utf-8")).hexdigest()
            != self.normalized_envelope_digest
        ):
            raise ValueError("Envelope snapshot digest mismatch")
        if (
            content_digest_payload(self.model_dump(mode="json", exclude={"result_digest"}))
            != self.result_digest
        ):
            raise ValueError("Result integrity mismatch")
        return self


def content_digest_payload(payload: dict[str, JsonValue]) -> str:
    from hashlib import sha256

    return sha256(canonical_json_object(payload).encode("utf-8")).hexdigest()


class AdapterOutcome(Snapshot):
    validation: ValidationReport
    result: ExternalModelResult | None = None

    @model_validator(mode="after")
    def no_invalid_result(self) -> Self:
        if self.result is None:
            if self.validation.status != "INVALID":
                raise ValueError("Missing normalized result")
        elif self.result.validation != self.validation:
            raise ValueError("Outcome status differs from result")
        return self
