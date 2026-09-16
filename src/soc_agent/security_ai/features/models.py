"""Versioned data contracts; features are derived inputs, never observations."""

import hashlib
import math
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from soc_agent._json import canonical_json_object
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp, utc_now

Version = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9]+(?:\.[0-9]+){0,2}$")]


class Snapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


class FeatureDefinition(Snapshot):
    name: NonEmptyText
    data_type: Literal["int", "float", "bool", "str"]
    nullable: bool = Field(default=False, strict=True)
    description: NonEmptyText


class FeatureSchema(Snapshot):
    schema_name: NonEmptyText
    schema_version: Version
    features: tuple[FeatureDefinition, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_names(self) -> Self:
        names = [feature.name for feature in self.features]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate feature definitions")
        return self

    def validate_payload(self, payload: dict[str, JsonValue]) -> None:
        if set(payload) != {feature.name for feature in self.features}:
            raise ValueError("Feature names must exactly match the schema")
        types = {"int": int, "float": float, "bool": bool, "str": str}
        for feature in self.features:
            value = payload[feature.name]
            if value is None and feature.nullable:
                continue
            if type(value) is not types[feature.data_type]:
                raise ValueError("Feature value does not match its strict scalar type")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("Feature values must be finite")


class DatasetSchema(Snapshot):
    """Source dataset identity, not a dataset manager or training schema."""

    dataset_name: NonEmptyText
    dataset_version: Version
    record_schema_version: Version
    label_field: NonEmptyText | None = None


class DatasetRecordReference(Snapshot):
    dataset: DatasetSchema
    record_id: NonEmptyText


class SourceType(StrEnum):
    EVIDENCE = "evidence"
    DATASET = "dataset"
    STREAM = "stream"


class SourceReference(Snapshot):
    """Logical source identity; transport coordinates belong to source adapters."""

    source_type: SourceType
    source_name: NonEmptyText
    source_version: Version | None = None
    record_id: NonEmptyText


def _check_source_reference(
    ref: SourceReference,
    evidence_id: UUID | None,
    dataset_ref: DatasetRecordReference | None,
    record_schema_version: str,
) -> None:
    if (ref.source_type == SourceType.EVIDENCE) != (evidence_id is not None):
        raise ValueError("Evidence source kind and reference differ")
    if (ref.source_type == SourceType.DATASET) != (dataset_ref is not None):
        raise ValueError("Dataset source kind and reference differ")
    if evidence_id is not None and ref.record_id != str(evidence_id):
        raise ValueError("Evidence source identity differs")
    if dataset_ref is not None:
        dataset = dataset_ref.dataset
        if (ref.source_name, ref.source_version, ref.record_id, record_schema_version) != (
            dataset.dataset_name,
            dataset.dataset_version,
            dataset_ref.record_id,
            dataset.record_schema_version,
        ):
            raise ValueError("Dataset source identity differs")


class SecurityRecord(Snapshot):
    """Structured source for local extraction; offline rows need no incident."""

    record_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID | None = None
    record_type: NonEmptyText
    record_schema_version: Version
    source: NonEmptyText
    source_reference: SourceReference
    fields: str
    observed_at: UTCTimestamp
    source_evidence_id: UUID | None = None
    dataset_reference: DatasetRecordReference | None = None

    @field_validator("fields", mode="before")
    @classmethod
    def freeze_fields(cls, value: object) -> str:
        return canonical_json_object(value)

    def payload(self) -> dict[str, JsonValue]:
        return TypeAdapter(dict[str, JsonValue]).validate_json(self.fields, strict=True)

    @model_validator(mode="after")
    def check_binding(self) -> Self:
        _check_source_reference(
            self.source_reference,
            self.source_evidence_id,
            self.dataset_reference,
            self.record_schema_version,
        )
        if self.source_evidence_id is not None and self.incident_id is None:
            raise ValueError("Evidence references require an incident")
        if self.dataset_reference is not None:
            dataset = self.dataset_reference.dataset
            if dataset.record_schema_version != self.record_schema_version:
                raise ValueError("Dataset and record schema versions differ")
            if dataset.label_field is not None and dataset.label_field not in self.payload():
                raise ValueError("Declared dataset label field is missing")
        return self


class FeatureSourceReference(Snapshot):
    record_id: UUID
    record_type: NonEmptyText
    record_schema_version: Version
    source: NonEmptyText
    source_reference: SourceReference
    observed_at: UTCTimestamp
    content_digest: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    source_evidence_id: UUID | None = None
    dataset_reference: DatasetRecordReference | None = None

    @model_validator(mode="after")
    def check_binding(self) -> Self:
        _check_source_reference(
            self.source_reference,
            self.source_evidence_id,
            self.dataset_reference,
            self.record_schema_version,
        )
        return self


class FeatureExtractionProvenance(Snapshot):
    extractor_name: NonEmptyText
    extractor_version: Version
    incident_id: UUID | None = None
    sources: tuple[FeatureSourceReference, ...] = Field(min_length=1)

    @property
    def source_record_ids(self) -> tuple[UUID, ...]:
        return tuple(source.record_id for source in self.sources)

    @property
    def source_evidence_ids(self) -> tuple[UUID, ...]:
        return tuple(s.source_evidence_id for s in self.sources if s.source_evidence_id is not None)

    @model_validator(mode="after")
    def unique_sources(self) -> Self:
        source_keys = [
            (
                s.source_reference.source_type,
                s.source_reference.source_name,
                s.source_reference.source_version,
                s.source_reference.record_id,
            )
            for s in self.sources
        ]
        for ids in (self.source_record_ids, self.source_evidence_ids, source_keys):
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate source references")
        if self.source_evidence_ids and self.incident_id is None:
            raise ValueError("Evidence provenance requires an incident")
        return self


class FeatureSet(Snapshot):
    """Validated shape; use create_feature_set for checked source binding.

    Full feature schema is retained to permit standalone validation. All features
    are required; nullable permits explicit null, never implicit imputation.
    """

    feature_set_id: UUID = Field(default_factory=uuid4)
    feature_schema: FeatureSchema
    values: str
    provenance: FeatureExtractionProvenance
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @field_validator("values", mode="before")
    @classmethod
    def freeze_values(cls, value: object) -> str:
        return canonical_json_object(value)

    def input_payload(self) -> dict[str, JsonValue]:
        payload = TypeAdapter(dict[str, JsonValue]).validate_json(self.values, strict=True)
        return {name: payload[name] for name in self.feature_names}

    @property
    def feature_names(self) -> tuple[str, ...]:
        return tuple(feature.name for feature in self.feature_schema.features)

    @property
    def feature_values(self) -> tuple[JsonValue, ...]:
        return tuple(self.input_payload().values())

    @property
    def input_fingerprint(self) -> str:
        content = canonical_json_object(
            {
                "schema_name": self.feature_schema.schema_name,
                "schema_version": self.feature_schema.schema_version,
                "extractor_name": self.provenance.extractor_name,
                "extractor_version": self.provenance.extractor_version,
                "feature_names": list(self.feature_names),
                "feature_values": list(self.feature_values),
            }
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @model_validator(mode="after")
    def validate_features(self) -> Self:
        payload = TypeAdapter(dict[str, JsonValue]).validate_json(self.values, strict=True)
        self.feature_schema.validate_payload(payload)
        for source in self.provenance.sources:
            if source.dataset_reference is not None:
                if source.dataset_reference.dataset.label_field in self.feature_names:
                    raise ValueError("Dataset labels cannot be inference features")
        return self
