"""Snapshot-validated human review ledger, separate from all runtime approvals."""

from sqlite3 import Connection, Row
from typing import cast

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review.models import (
    BlockingReason,
    ImprovementReviewRecord,
    ImprovementReviewRequest,
    ReviewRequestContent,
    safety_counts,
)
from soc_agent.offline_comparison.models import (
    OfflineCandidateVariant,
    OfflineComparison,
    OfflineEvaluationResult,
    VerdictState,
)
from soc_agent.offline_comparison.store import Artifact, ExpectedCache, OfflineComparisonStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class ImprovementReviewStore:
    def __init__(self, comparisons: OfflineComparisonStore) -> None:
        self.comparisons = comparisons
        self.database = comparisons.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (13, 14):
                raise UnsupportedSchemaError("Explicit improvement review migration required")
            for table in ("improvement_review_requests", "improvement_review_records"):
                connection.execute(f"SELECT id FROM {table} LIMIT 0")

    def _content(self, connection: Connection, comparison_id: str) -> ReviewRequestContent:
        cache: ExpectedCache = {}

        def load(table: str, artifact_id: str) -> Artifact:
            row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (artifact_id,)).fetchone()
            if row is None:
                raise StoredDataError("Missing review source artifact")
            return self.comparisons._decode(connection, table, row, expected_cache=cache)

        comparison = cast(OfflineComparison, load("offline_comparisons", comparison_id))
        binding = comparison.content.binding
        baseline = cast(
            OfflineEvaluationResult,
            load("offline_evaluation_results", comparison.content.baseline_result.identity),
        )
        candidate_result = cast(
            OfflineEvaluationResult,
            load("offline_evaluation_results", comparison.content.candidate_result.identity),
        )
        if candidate_result.content.variant is None:
            raise StoredDataError("Candidate variant reference missing")
        variant = cast(
            OfflineCandidateVariant,
            load("offline_candidate_variants", candidate_result.content.variant.identity),
        )
        if any(v.content.binding != binding for v in (variant, baseline, candidate_result)):
            raise StoredDataError("Cross-candidate review graph")
        candidate, facts = self.comparisons.planning._source(
            connection, binding.source.candidate.identity
        )
        if not facts:
            raise StoredDataError("Review source samples missing")
        reasons = []
        if variant.content.construction_status != "CONSTRUCTIBLE":
            reasons.append(BlockingReason.VARIANT_NOT_CONSTRUCTIBLE)
        if binding.frozen_baseline is None:
            reasons.append(BlockingReason.BASELINE_UNAVAILABLE)
        if any(r.content.execution_status != "EXECUTED" for r in (baseline, candidate_result)):
            reasons.append(BlockingReason.NO_EXECUTED_COMPARISON)
        if not any(m.delta is not None for m in comparison.content.metrics):
            reasons.append(BlockingReason.NO_MEASURABLE_RESULT)
        blockers = []
        statuses = tuple(s for i in comparison.content.safety for s in (i.baseline, i.candidate))
        if VerdictState.FAIL in statuses:
            blockers.append(BlockingReason.SAFETY_FAIL)
        if VerdictState.UNKNOWN in statuses:
            blockers.append(BlockingReason.SAFETY_UNKNOWN)
        if any(c.status == VerdictState.FAIL for c in comparison.content.acceptance):
            blockers.append(BlockingReason.ACCEPTANCE_FAIL)
        if any(c.status == VerdictState.UNKNOWN for c in comparison.content.acceptance):
            blockers.append(BlockingReason.ACCEPTANCE_UNKNOWN)
        return ReviewRequestContent(
            binding=binding,
            variant=ArtifactReference(
                identity=variant.variant_id, digest=content_digest(variant.content)
            ),
            baseline_result=comparison.content.baseline_result,
            candidate_result=comparison.content.candidate_result,
            comparison=ArtifactReference(
                identity=comparison_id, digest=content_digest(comparison.content)
            ),
            candidate=candidate.content,
            summary=comparison.content,
            limitations=tuple(
                sorted(
                    set(
                        baseline.content.blockers
                        + candidate_result.content.blockers
                        + ("OFFLINE_RESULTS_DO_NOT_ESTABLISH_PRODUCTION_SAFETY",)
                        + (
                            ("UNRESOLVED_SAFETY_EVIDENCE",)
                            if VerdictState.UNKNOWN in statuses
                            else ()
                        )
                    )
                )
            ),
            reviewability="NOT_REVIEWABLE" if reasons else "REVIEWABLE",
            blocking_reasons=tuple(sorted(reasons)),
            approval_blockers=tuple(sorted(blockers)),
            baseline_safety_counts=safety_counts(
                tuple(i.baseline for i in comparison.content.safety)
            ),
            candidate_safety_counts=safety_counts(
                tuple(i.candidate for i in comparison.content.safety)
            ),
            # Existing confirmation infrastructure requires an incident scope. This
            # is a validated supporting incident, NOT an Incident Review decision.
            authorization_incident=next(
                f.sources.incident_id
                for f in facts
                if f.sample.identity == binding.source.supporting_sample_refs[0].identity
            ),
        )

    def create_request(self, comparison_id: str) -> ImprovementReviewRequest:
        with self.database.transaction() as connection:
            content = self._content(connection, comparison_id)
            value = ImprovementReviewRequest(
                review_request_id=content_digest(content), content=content
            )
            row = connection.execute(
                "SELECT * FROM improvement_review_requests WHERE id=?", (value.review_request_id,)
            ).fetchone()
            if row is not None:
                old = self._request(connection, row)
                if old.content != content:
                    raise StoredDataError("Conflicting review identity")
                return old
            connection.execute(
                "INSERT INTO improvement_review_requests VALUES (?,?,?,?,?)",
                (
                    value.review_request_id,
                    content.binding.source.candidate.identity,
                    comparison_id,
                    ledger.serialize(value),
                    content_digest(value),
                ),
            )
            return value

    def _request(self, connection: Connection, row: Row | None) -> ImprovementReviewRequest:
        if row is None:
            raise StoredDataError("Unknown improvement review request")
        value = ledger.decode(ImprovementReviewRequest, row)
        if (
            value.review_request_id,
            value.content.binding.source.candidate.identity,
            value.content.comparison.identity,
        ) != (row["id"], row["candidate_id"], row["comparison_id"]):
            raise StoredDataError("Review request indexed binding mismatch")
        if value.content != self._content(connection, row["comparison_id"]):
            raise StoredDataError("Review request does not match pinned evidence")
        return value

    def _record(self, connection: Connection, row: Row | None) -> ImprovementReviewRecord:
        if row is None:
            raise StoredDataError("Unknown improvement review record")
        value = ledger.decode(ImprovementReviewRecord, row)
        request = self._request(
            connection,
            connection.execute(
                "SELECT * FROM improvement_review_requests WHERE id=?", (row["request_id"],)
            ).fetchone(),
        )
        if (
            value.review_record_id,
            value.submission.review_request.identity,
            value.snapshot.binding.source.candidate.identity,
        ) != (
            row["id"],
            row["request_id"],
            row["candidate_id"],
        ) or value.snapshot != request.content:
            raise StoredDataError("Review record indexed/snapshot binding mismatch")
        v = value.verification
        receipt = SQLiteConfirmationConsumer._load(connection, v.provider_id, v.confirmation_id)
        if receipt is None or not receipt.consumed or receipt.verification != v:
            raise StoredDataError("Improvement review confirmation receipt mismatch")
        return value

    def get_review_request(self, request_id: str) -> ImprovementReviewRequest:
        with self.database.transaction(write=False) as connection:
            return self._request(
                connection,
                connection.execute(
                    "SELECT * FROM improvement_review_requests WHERE id=?", (request_id,)
                ).fetchone(),
            )

    def get_review_record(self, record_id: str) -> ImprovementReviewRecord:
        with self.database.transaction(write=False) as connection:
            return self._record(
                connection,
                connection.execute(
                    "SELECT * FROM improvement_review_records WHERE id=?", (record_id,)
                ).fetchone(),
            )

    def get_review_record_for_request(self, request_id: str) -> ImprovementReviewRecord | None:
        with self.database.transaction(write=False) as connection:
            self._request(
                connection,
                connection.execute(
                    "SELECT * FROM improvement_review_requests WHERE id=?", (request_id,)
                ).fetchone(),
            )
            row = connection.execute(
                "SELECT * FROM improvement_review_records WHERE request_id=?", (request_id,)
            ).fetchone()
            return None if row is None else self._record(connection, row)

    def list_review_requests(self, candidate_id: str) -> tuple[ImprovementReviewRequest, ...]:
        with self.database.transaction(write=False) as connection:
            self.comparisons.planning._source(connection, candidate_id)
            return tuple(
                self._request(connection, row)
                for row in connection.execute(
                    "SELECT * FROM improvement_review_requests WHERE candidate_id=? ORDER BY id",
                    (candidate_id,),
                )
            )

    def list_review_records(self, candidate_id: str) -> tuple[ImprovementReviewRecord, ...]:
        with self.database.transaction(write=False) as connection:
            self.comparisons.planning._source(connection, candidate_id)
            return tuple(
                self._record(connection, row)
                for row in connection.execute(
                    "SELECT * FROM improvement_review_records WHERE candidate_id=? ORDER BY id",
                    (candidate_id,),
                )
            )
