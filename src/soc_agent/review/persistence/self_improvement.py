"""One read snapshot of content-addressed learning history, never recompute learning."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID

from pydantic import BaseModel

from soc_agent.evaluation.models import EvaluationRecord
from soc_agent.experience.models import Experience
from soc_agent.feedback.models import AnalystFeedback
from soc_agent.improvement_candidates.models import FailurePattern, ImprovementCandidate
from soc_agent.improvement_dataset.models import ImprovementDataset, ImprovementSample
from soc_agent.improvement_promotion.models import (
    FAMILY,
    ActivationRecord,
    ActivePointer,
    PromotionRequest,
    RollbackRequest,
    VersionedImprovementArtifact,
    action_context,
)
from soc_agent.improvement_review.models import ImprovementReviewRecord, ImprovementReviewRequest
from soc_agent.offline_comparison.coverage_models import FrozenBaseline
from soc_agent.offline_comparison.models import (
    OfflineCandidateVariant,
    OfflineComparison,
    OfflineEvaluationResult,
)
from soc_agent.offline_evaluation.models import (
    CandidateTestPlan,
    EvaluationSpecification,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError

# Private fixed query schema, never supplied by a browser.
TABLES = {
    "experiences": (Experience, "experience_id"),
    "evaluations": (EvaluationRecord, "evaluation_id"),
    "analyst_feedback": (AnalystFeedback, "feedback_id"),
    "improvement_samples": (ImprovementSample, "sample_id"),
    "improvement_datasets": (ImprovementDataset, "dataset_id"),
    "failure_patterns": (FailurePattern, "pattern_id"),
    "improvement_candidates": (ImprovementCandidate, "candidate_id"),
    "offline_evaluation_specifications": (EvaluationSpecification, "specification_id"),
    "candidate_test_plans": (CandidateTestPlan, "plan_id"),
    "offline_candidate_variants": (OfflineCandidateVariant, "variant_id"),
    "frozen_offline_baselines": (FrozenBaseline, "baseline_id"),
    "offline_evaluation_results": (OfflineEvaluationResult, "result_id"),
    "offline_comparisons": (OfflineComparison, "comparison_id"),
    "improvement_review_requests": (ImprovementReviewRequest, "review_request_id"),
    "improvement_review_records": (ImprovementReviewRecord, "review_record_id"),
    "improvement_artifacts": (VersionedImprovementArtifact, "artifact_id"),
    "improvement_promotion_requests": (PromotionRequest, "request_id"),
    "improvement_rollback_requests": (RollbackRequest, "request_id"),
    "improvement_promotion_records": (ActivationRecord, "record_id"),
    "improvement_rollback_records": (ActivationRecord, "record_id"),
}


@dataclass(frozen=True)
class SelfImprovementSnapshot:
    records: Mapping[str, Mapping[str, BaseModel]]
    pointer: ActivePointer | None
    visible_incidents: frozenset[UUID]


def read_self_improvement(
    store: SQLiteGovernanceStore, visible: Callable[[UUID], bool]
) -> SelfImprovementSnapshot:
    with store.database.transaction(write=False) as connection:
        connection.execute("PRAGMA query_only=ON")
        tables = {
            r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        version = store.database.core_schema_version(connection)
        if version > 14:
            raise StoredDataError("Unsupported learning schema version")
        if version >= 14 and not set(TABLES) <= tables:
            raise StoredDataError("Learning schema has missing durable tables")
        records = {}
        for table, (model, field) in TABLES.items():
            if table not in tables:
                continue
            values = {}
            for row in connection.execute(f"SELECT * FROM {table}"):
                value = ledger.decode(model, row)
                identity = getattr(value, field)
                index = field if field in row.keys() else "id"
                if row[index] != identity:
                    raise StoredDataError("Learning artifact index mismatch")
                values[identity] = value
            records[table] = values

        def pinned(table, ref, *, content=False):
            value = records.get(table, {}).get(ref.identity)
            if value is None or content_digest(value.content if content else value) != ref.digest:
                raise StoredDataError("Learning pinned source mismatch")
            return value

        for value in records.get("evaluations", {}).values():
            source = records["experiences"].get(value.content.experience_id)
            if source is None or content_digest(source) != value.content.experience_digest:
                raise StoredDataError("Outcome experience mismatch")
        for value in records.get("analyst_feedback", {}).values():
            request = value.request
            for table, identity, digest in (
                ("experiences", request.experience_id, request.experience_digest),
                ("evaluations", request.evaluation_id, request.evaluation_digest),
            ):
                source = records.get(table, {}).get(identity)
                if source is None or content_digest(source) != digest:
                    raise StoredDataError("Feedback historical source mismatch")
        for sample in records.get("improvement_samples", {}).values():
            sources = sample.content.sources
            pinned("experiences", sources.experience)
            pinned("evaluations", sources.evaluation)
            for ref in sources.feedback:
                pinned("analyst_feedback", ref)
        for dataset in records.get("improvement_datasets", {}).values():
            for ref in dataset.manifest.samples:
                pinned("improvement_samples", ref)
            for selected in dataset.manifest.selection:
                pinned("experiences", selected.sources.experience)
                pinned("evaluations", selected.sources.evaluation)
                for ref in selected.sources.feedback:
                    pinned("analyst_feedback", ref)
        for pattern in records.get("failure_patterns", {}).values():
            if pattern.content.dataset.dataset_id not in records.get("improvement_datasets", {}):
                raise StoredDataError("Pattern dataset missing")
        for candidate in records.get("improvement_candidates", {}).values():
            for ref in candidate.content.failure_pattern_refs:
                pattern = pinned("failure_patterns", ref, content=True)
                if (
                    pattern.content.dataset != candidate.content.dataset
                    or candidate.content.supporting_sample_refs
                    != pattern.content.supporting_sample_refs
                ):
                    raise StoredDataError("Candidate pattern/support binding mismatch")
            for ref in candidate.content.supporting_sample_refs:
                pinned("improvement_samples", ref)
        for value in records.get("offline_comparisons", {}).values():
            for ref in (value.content.baseline_result, value.content.candidate_result):
                result = pinned("offline_evaluation_results", ref, content=True)
                if result.content.binding != value.content.binding:
                    raise StoredDataError("Comparison result binding mismatch")
        for value in records.get("offline_evaluation_results", {}).values():
            b = value.content.binding
            pinned("improvement_candidates", b.source.candidate, content=True)
            spec = pinned("offline_evaluation_specifications", b.specification, content=True)
            plan = pinned("candidate_test_plans", b.test_plan, content=True)
            if (
                spec.content.binding != b.source
                or plan.content.binding != b.source
                or plan.content.specification != b.specification
                or plan.content.split != b.split
                or spec.content.partition.split_id != b.split.identity
                or content_digest(spec.content.partition.content) != b.split.digest
            ):
                raise StoredDataError("Offline split/source binding mismatch")
            # Partitions are embedded in specifications; no durable partition table.
            if b.frozen_baseline:
                pinned("frozen_offline_baselines", b.frozen_baseline, content=True)
            if value.content.variant:
                pinned("offline_candidate_variants", value.content.variant, content=True)
        for request in records.get("improvement_review_requests", {}).values():
            c = request.content
            comparison = pinned("offline_comparisons", c.comparison, content=True)
            candidate = pinned("improvement_candidates", c.binding.source.candidate, content=True)
            if comparison.content != c.summary or candidate.content != c.candidate:
                raise StoredDataError("Review convenience snapshot mismatch")
            pinned("offline_candidate_variants", c.variant, content=True)

        def receipt(verification):
            saved = SQLiteConfirmationConsumer._load(
                connection, verification.provider_id, verification.confirmation_id
            )
            if saved is None or not saved.consumed or saved.verification != verification:
                raise StoredDataError("Learning governance receipt mismatch")

        for record in records.get("improvement_review_records", {}).values():
            request = pinned(
                "improvement_review_requests", record.submission.review_request, content=True
            )
            if request.content != record.snapshot:
                raise StoredDataError("Review record snapshot mismatch")
            receipt(record.verification)
        for artifact in records.get("improvement_artifacts", {}).values():
            source = artifact.content.source_snapshot
            request = pinned("improvement_review_requests", source.review_request, content=True)
            record = pinned("improvement_review_records", source.review_record)
            if request.content != source.snapshot or record.snapshot != source.snapshot:
                raise StoredDataError("Version source snapshot mismatch")
        activations = []
        for kind in ("promotion", "rollback"):
            for record in records.get(f"improvement_{kind}_records", {}).values():
                request = pinned(f"improvement_{kind}_requests", record.request, content=True)
                artifact = pinned(
                    "improvement_artifacts", record.current.active_artifact, content=True
                )
                if (
                    record.action != kind.upper()
                    or record.previous != request.content.expected
                    or record.current.active_version != artifact.content.version
                    or record.verification.context != action_context(request)
                ):
                    raise StoredDataError("Activation audit mismatch")
                if kind == "promotion" and (
                    artifact.content.payload != request.content.payload
                    or artifact.content.source_snapshot != request.content.source_snapshot
                ):
                    raise StoredDataError("Promotion artifact mismatch")
                if kind == "rollback" and record.current.active_artifact != request.content.target:
                    raise StoredDataError("Rollback artifact mismatch")
                receipt(record.verification)
                activations.append(record)
        pointer = None
        artifacts = records.get("improvement_artifacts", {})
        if sorted(v.content.version for v in artifacts.values()) != list(
            range(1, len(artifacts) + 1)
        ):
            raise StoredDataError("Registry version sequence mismatch")
        for artifact in artifacts.values():
            registrations = [
                r
                for r in activations
                if r.action == "PROMOTION"
                and r.current.active_artifact.identity == artifact.artifact_id
            ]
            if len(registrations) != 1:
                raise StoredDataError("Version has no unique promotion registration")
        if "improvement_active_pointers" in tables:
            rows = connection.execute("SELECT * FROM improvement_active_pointers").fetchall()
            if len(rows) > 1 or any(r["family"] != FAMILY for r in rows):
                raise StoredDataError("Unsupported active family")
            pointer = ActivePointer()
            previous = pointer
            for revision, record in enumerate(
                sorted(activations, key=lambda v: v.current.revision), 1
            ):
                if record.current.revision != revision or record.previous != previous:
                    raise StoredDataError("Activation revision chain mismatch")
                previous = record.current
            if rows:
                row = rows[0]
                if (
                    previous.active_artifact is None
                    or previous.active_artifact.identity != row["artifact_id"]
                    or previous.active_version != row["version"]
                    or previous.revision != row["revision"]
                ):
                    raise StoredDataError("Active pointer lacks audit binding")
                pointer = previous
            elif activations or records.get("improvement_artifacts"):
                raise StoredDataError("Registered history has no active pointer")
        identities = {UUID(r[0]) for r in connection.execute("SELECT incident_id FROM incidents")}
        return SelfImprovementSnapshot(
            MappingProxyType({t: MappingProxyType(v) for t, v in records.items()}),
            pointer,
            frozenset(i for i in identities if visible(i)),
        )
