"""Safe immutable projections, separate from governance command and authority models."""

from typing import Literal
from uuid import UUID

from soc_agent.review.models import Frozen
from soc_agent.state.evidence import UTCTimestamp


class LearningRecordView(Frozen):
    identity: str
    title: str
    facts: tuple[tuple[str, str], ...]
    incidents: tuple[UUID, ...] = ()
    created_at: UTCTimestamp | None = None


class LearningSection(Frozen):
    name: str
    available: bool
    records: tuple[LearningRecordView, ...]


class ComparisonView(Frozen):
    identity: str
    candidate_id: str
    dataset_id: str
    development_count: int
    holdout_count: int
    baseline_id: str
    candidate_result_id: str
    metrics: tuple[tuple[str, str, str, str, str], ...]
    safety: tuple[tuple[str, str, str], ...]
    acceptance: tuple[tuple[str, str, str], ...]
    created_at: UTCTimestamp


class VersionView(Frozen):
    artifact_id: str
    family: str
    version: int
    operation: str
    permissions: tuple[str, ...]
    source_candidate: str
    active: bool
    promotion_records: tuple[str, ...]
    rollback_from: tuple[str, ...]
    rollback_to: tuple[str, ...]
    created_at: UTCTimestamp


class ActiveVersionView(Frozen):
    state: Literal["NONE", "ACTIVE", "UNKNOWN"]
    artifact: VersionView | None = None
    pointer_revision: int | None = None
    activation_record: str | None = None
    activated_at: UTCTimestamp | None = None
    runtime_consumption: Literal["UNKNOWN"] = "UNKNOWN"


class SelfImprovementView(Frozen):
    experience_count: int | None
    candidate_count: int | None
    awaiting_review_count: int | None
    rollback_target_count: int | None
    active: ActiveVersionView
    sections: tuple[LearningSection, ...]
    comparisons: tuple[ComparisonView, ...]
    versions: tuple[VersionView, ...]
    lifecycle_counts: tuple[tuple[str, int | None], ...]
    promotion_ux: Literal["READ_ONLY"] = "READ_ONLY"
    rollback_ux: Literal["READ_ONLY"] = "READ_ONLY"
