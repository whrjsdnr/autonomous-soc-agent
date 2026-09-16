"""Synchronous, local extraction with explicit source validation and no inference."""

import hashlib
from dataclasses import dataclass
from typing import Annotated, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.features.models import (
    FeatureDefinition,
    FeatureExtractionProvenance,
    FeatureSchema,
    FeatureSet,
    FeatureSourceReference,
    SecurityRecord,
    SourceReference,
    SourceType,
)
from soc_agent.state import IncidentState


class FeatureExtractionError(ValueError):
    """Invalid source, calculation, or output; public messages omit raw data."""


class FeatureProvenanceError(FeatureExtractionError):
    """Source references or incident binding do not match the supplied state."""


def record_from_evidence(
    *, state: IncidentState, evidence_id: UUID, record_type: str, record_schema_version: str
) -> SecurityRecord:
    """Resolve the actual Evidence, parse its JSON object, and detach its fields."""
    try:
        state = IncidentState.model_validate(state.model_dump(warnings=False))
        evidence = next((e for e in state.evidence if e.evidence_id == evidence_id), None)
        if evidence is None:
            raise FeatureProvenanceError("Source evidence must exist in this incident")
        return SecurityRecord(
            incident_id=state.incident_id,
            record_type=record_type,
            record_schema_version=record_schema_version,
            source=evidence.source,
            source_reference=SourceReference(
                source_type=SourceType.EVIDENCE,
                source_name=evidence.source,
                record_id=str(evidence.evidence_id),
            ),
            fields=evidence.raw_data,
            observed_at=evidence.observed_at,
            source_evidence_id=evidence.evidence_id,
        )
    except FeatureProvenanceError:
        raise
    except (ValueError, TypeError):
        raise FeatureExtractionError("Evidence is not a valid structured source record") from None


def _validate_sources(
    records: tuple[SecurityRecord, ...], state: IncidentState | None
) -> tuple[SecurityRecord, ...]:
    try:
        records = tuple(
            SecurityRecord.model_validate(r.model_dump(warnings=False)) for r in records
        )
        if not records:
            raise ValueError("Sources required")
        if state is not None:
            state = IncidentState.model_validate(state.model_dump(warnings=False))
        incidents = {record.incident_id for record in records}
        if len(incidents) != 1:
            raise ValueError("Mixed incident sources")
        incident_id = records[0].incident_id
        if incident_id is not None and (state is None or state.incident_id != incident_id):
            raise ValueError("Incident source requires matching state")
        if state is not None and incident_id != state.incident_id:
            raise ValueError("Offline records must not implicitly bind to an incident")
        evidence = {e.evidence_id: e for e in state.evidence} if state is not None else {}
        for record in records:
            if record.source_evidence_id is None:
                continue
            original = evidence.get(record.source_evidence_id)
            if original is None or original.incident_id != incident_id:
                raise ValueError("Unknown or foreign evidence")
            if (
                canonical_json_object(original.raw_data) != record.fields
                or original.source != record.source
                or original.source != record.source_reference.source_name
                or original.observed_at != record.observed_at
            ):
                raise ValueError("Structured record differs from referenced evidence")
        return records
    except (ValueError, TypeError):
        raise FeatureProvenanceError("Invalid feature source provenance") from None


def create_feature_set(
    *,
    feature_schema: FeatureSchema,
    values: dict[str, JsonValue],
    records: tuple[SecurityRecord, ...],
    extractor_name: str,
    extractor_version: str,
    state: IncidentState | None = None,
) -> FeatureSet:
    """Trusted transformation boundary; validates references, not arbitrary Python logic.

    Versioned extractors supply values. The factory cannot prove those values were
    calculated correctly; concrete extractors and their tests own that guarantee.
    """
    records = _validate_sources(records, state)
    try:
        schema = FeatureSchema.model_validate(feature_schema.model_dump(warnings=False))
        sources = tuple(
            FeatureSourceReference(
                record_id=r.record_id,
                record_type=r.record_type,
                record_schema_version=r.record_schema_version,
                source=r.source,
                source_reference=r.source_reference,
                observed_at=r.observed_at,
                content_digest=hashlib.sha256(r.fields.encode("utf-8")).hexdigest(),
                source_evidence_id=r.source_evidence_id,
                dataset_reference=r.dataset_reference,
            )
            for r in records
        )
        return FeatureSet(
            feature_schema=schema,
            values=values,
            provenance=FeatureExtractionProvenance(
                extractor_name=extractor_name,
                extractor_version=extractor_version,
                incident_id=records[0].incident_id,
                sources=sources,
            ),
        )
    except (ValueError, TypeError):
        raise FeatureExtractionError("Invalid feature contract or values") from None


class FeatureExtractor(Protocol):
    def extract(
        self, record: SecurityRecord, *, state: IncidentState | None = None
    ) -> FeatureSet: ...


class _AuthenticationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    failed_login_count: Annotated[int, Field(ge=0)]
    successful_login_count: Annotated[int, Field(ge=0)]
    unique_accounts: Annotated[int, Field(ge=0)]
    window_seconds: Annotated[int, Field(gt=0)]


@dataclass(frozen=True)
class AuthenticationSummaryExtractor:
    """Fixture contract v1: integer counts/window, no rounding or imputation."""

    def extract(self, record: SecurityRecord, *, state: IncidentState | None = None) -> FeatureSet:
        record = _validate_sources((record,), state)[0]
        if (
            record.record_type != "authentication_summary"
            or record.record_schema_version != "1.0.0"
        ):
            raise FeatureExtractionError("Unsupported authentication source contract")
        try:
            payload = record.payload()
            if record.dataset_reference is not None:
                label = record.dataset_reference.dataset.label_field
                if label is not None:
                    payload.pop(label)
            source = _AuthenticationInput.model_validate(payload)
            total = source.failed_login_count + source.successful_login_count
            if total == 0:
                raise ValueError("Failure rate is undefined for an empty window")
            values = {
                "failed_login_count": source.failed_login_count,
                "unique_accounts": source.unique_accounts,
                "failure_rate": source.failed_login_count / total,
                "login_velocity": total / source.window_seconds,
            }
        except (ValueError, TypeError, OverflowError):
            raise FeatureExtractionError(
                "Invalid authentication source or derived calculation"
            ) from None
        return create_feature_set(
            feature_schema=FeatureSchema(
                schema_name="auth_features",
                schema_version="1.0.0",
                features=(
                    FeatureDefinition(
                        name="failed_login_count", data_type="int", description="Failed attempts"
                    ),
                    FeatureDefinition(
                        name="unique_accounts", data_type="int", description="Distinct accounts"
                    ),
                    FeatureDefinition(
                        name="failure_rate",
                        data_type="float",
                        description="Failed / total attempts",
                    ),
                    FeatureDefinition(
                        name="login_velocity",
                        data_type="float",
                        description="Total attempts per second",
                    ),
                ),
            ),
            values=values,
            records=(record,),
            extractor_name="auth_summary",
            extractor_version="1.0.0",
            state=state,
        )
