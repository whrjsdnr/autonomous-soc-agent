"""Fail-closed source validation before introducing production activation."""

from enum import StrEnum
from sqlite3 import Connection
from typing import Literal

from soc_agent.improvement_candidates.models import (
    CandidateType,
    CoverageProposal,
    ImprovementCandidate,
)
from soc_agent.improvement_candidates.strategy import compile_candidate_strategy
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.improvement_review.models import BlockingReason, ReviewDecision
from soc_agent.improvement_review.store import ImprovementReviewStore
from soc_agent.offline_comparison.models import CONTRACT_EVALUATOR_VERSION, OfflineEvaluationResult
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError


class PromotionReason(StrEnum):
    UNSUPPORTED_CANDIDATE_TYPE = "UNSUPPORTED_CANDIDATE_TYPE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    REVIEW_NOT_APPROVED = "REVIEW_NOT_APPROVED"
    EVALUATION_NOT_MEASURABLE = "EVALUATION_NOT_MEASURABLE"
    ACCEPTANCE_NOT_PASS = "ACCEPTANCE_NOT_PASS"
    SAFETY_FAILED = "SAFETY_FAILED"
    SAFETY_UNKNOWN = "SAFETY_UNKNOWN"
    RUNTIME_CONTRACT_UNAVAILABLE = "RUNTIME_CONTRACT_UNAVAILABLE"


class PromotionEligibility(Frozen):
    eligibility_version: Literal["soc-improvement-promotion-eligibility:v2"] = (
        "soc-improvement-promotion-eligibility:v2"
    )
    review_request: ArtifactReference
    candidate: ArtifactReference
    comparison: ArtifactReference
    review_record: ArtifactReference | None
    status: Literal["NON_PROMOTABLE", "PROMOTABLE"]
    reasons: tuple[PromotionReason, ...]
    authority: Literal["ELIGIBILITY_IS_NOT_PROMOTION_AUTHORIZATION"] = (
        "ELIGIBILITY_IS_NOT_PROMOTION_AUTHORIZATION"
    )


class PromotionEligibilityService:
    """Revalidate the entire pinned graph in one read transaction.

    Integrity errors propagate from the existing source verifiers. Missing approval
    is a normal eligibility reason; missing/corrupt referenced sources are not.
    There is intentionally no activation, bootstrap, or confirmation consumption.
    """

    def __init__(self, reviews: ImprovementReviewStore) -> None:
        self.reviews = reviews

    def assess(self, review_request_id: str) -> PromotionEligibility:
        with self.reviews.database.transaction(write=False) as connection:
            return self.assess_in_transaction(connection, review_request_id)

    def assess_in_transaction(
        self, connection: Connection, review_request_id: str
    ) -> PromotionEligibility:
        request = self.reviews._request(
            connection,
            connection.execute(
                "SELECT * FROM improvement_review_requests WHERE id=?",
                (review_request_id,),
            ).fetchone(),
        )
        row = connection.execute(
            "SELECT * FROM improvement_review_records WHERE request_id=?",
            (review_request_id,),
        ).fetchone()
        record = None if row is None else self.reviews._record(connection, row)
        content = request.content
        reasons: set[PromotionReason] = set()
        proposal = content.candidate.proposal
        if proposal.candidate_type != CandidateType.INVESTIGATION_STRATEGY:
            reasons.add(PromotionReason.UNSUPPORTED_CANDIDATE_TYPE)
        if proposal.operation != "REQUIRE_READ_ONLY_PERMISSION_COVERAGE":
            reasons.add(PromotionReason.UNSUPPORTED_OPERATION)
        # _request has already revalidated this exact result and its complete
        # parent graph in the same read snapshot. Decode its pinned evidence
        # without interpreting legacy v2 selections as production validation.
        result_row = connection.execute(
            "SELECT * FROM offline_evaluation_results WHERE id=?",
            (content.candidate_result.identity,),
        ).fetchone()
        if result_row is None:
            raise StoredDataError("Missing promotion eligibility result")
        result = ledger.decode(OfflineEvaluationResult, result_row)
        if content_digest(result.content) != content.candidate_result.digest:
            raise StoredDataError("Promotion eligibility result binding mismatch")
        evidence = result.content.strategy_safety
        contract_available = False
        if isinstance(proposal, CoverageProposal) and evidence is not None:
            candidate = ImprovementCandidate(
                candidate_id=content.binding.source.candidate.identity,
                candidate_version=content.binding.source.candidate.identity,
                content=content.candidate,
            )
            contract_available = (
                result.content.evaluator_version == CONTRACT_EVALUATOR_VERSION
                and evidence.strategy == compile_candidate_strategy(candidate)
                and evidence.plan_validation == "PASS"
            )
        if not contract_available:
            reasons.add(PromotionReason.RUNTIME_CONTRACT_UNAVAILABLE)
        if record is None or record.submission.decision != ReviewDecision.APPROVE:
            reasons.add(PromotionReason.REVIEW_NOT_APPROVED)
        if content.blocking_reasons:
            reasons.add(PromotionReason.EVALUATION_NOT_MEASURABLE)
        for blocker, reason in (
            (BlockingReason.SAFETY_FAIL, PromotionReason.SAFETY_FAILED),
            (BlockingReason.SAFETY_UNKNOWN, PromotionReason.SAFETY_UNKNOWN),
            (BlockingReason.ACCEPTANCE_FAIL, PromotionReason.ACCEPTANCE_NOT_PASS),
            (BlockingReason.ACCEPTANCE_UNKNOWN, PromotionReason.ACCEPTANCE_NOT_PASS),
        ):
            if blocker in content.approval_blockers:
                reasons.add(reason)
        return PromotionEligibility(
            review_request=ArtifactReference(
                identity=request.review_request_id, digest=content_digest(content)
            ),
            candidate=content.binding.source.candidate,
            comparison=content.comparison,
            review_record=None
            if record is None
            else ArtifactReference(identity=record.review_record_id, digest=content_digest(record)),
            reasons=tuple(sorted(reasons)),
            status="NON_PROMOTABLE" if reasons else "PROMOTABLE",
        )
