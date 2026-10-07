"""Immutable runtime monitoring projections; no raw features or offline metrics."""

from typing import Literal
from uuid import UUID

from soc_agent.review.models import Frozen
from soc_agent.state.evidence import UTCTimestamp

ModelKind = Literal["network_classifier", "network_anomaly", "authentication_anomaly"]


class RuntimeValue(Frozen):
    name: str
    value: float | bool


class FileDigestView(Frozen):
    path: str
    sha256: str


class RetainedModelView(Frozen):
    kind: ModelKind
    title: str
    adapter: str
    availability: Literal["AVAILABLE", "NOT AVAILABLE", "UNKNOWN"]
    metadata_available: bool
    model_name: str | None = None
    model_version: str | None = None
    manifest_digest: str | None = None
    file_hashes: tuple[FileDigestView, ...] = ()
    feature_schema: str | None = None
    extractor: str | None = None
    feature_count: int | None = None
    feature_names: tuple[str, ...] = ()
    signal_state: str = "UNKNOWN"
    last_observed: UTCTimestamp | None = None
    contribution_id: str | None = None
    incident_id: UUID | None = None
    run_id: UUID | None = None
    assessment_id: UUID | None = None
    fusion_id: str | None = None
    signal_ids: tuple[UUID, ...] = ()
    source_result_ids: tuple[UUID, ...] = ()
    source_types: tuple[str, ...] = ()
    source_record_count: int | None = None
    evidence_references: tuple[UUID, ...] = ()
    values: tuple[RuntimeValue, ...] = ()
    class_probabilities: tuple[tuple[str, float], ...] = ()
    score_semantics: str | None = None
    operating_point: str | None = None
    reported_coverage: str | None = None
    integrity_status: Literal["UNKNOWN"] = "UNKNOWN"


class FusionMonitorView(Frozen):
    fusion_id: str
    version: str
    incident_id: UUID
    run_id: UUID
    assessment_id: UUID
    checkpoint_revision: int
    snapshot_revision: int
    agreement: str
    coverage: str
    confidence: str
    created_at: UTCTimestamp | None
    contributions: tuple[tuple[str, str], ...]
    missing_models: tuple[str, ...]
    limitations: tuple[str, ...]
    cross_domain_state: str


class SecurityAIMonitorView(Frozen):
    models: tuple[RetainedModelView, ...]
    latest_retained_signals: tuple[RetainedModelView, ...]
    fusion_contexts: tuple[FusionMonitorView, ...]
    linked_incident_count: int
    retained_signal_count: int
    latest_signal_at: UTCTimestamp | None
    system_status: Literal["UNKNOWN"] = "UNKNOWN"
    scope: str = (
        "Authorized latest checkpoint contexts; "
        "not a complete signal history or live model inventory"
    )
