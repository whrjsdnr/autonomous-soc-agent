"""Human improvement governance; no executable content or promotion authority."""

import re
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.improvement_candidates.models import CandidateContent
from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.offline_comparison.models import (
    ComparisonContent,
    EvaluationBinding,
    VerdictState,
)
from soc_agent.review.authentication import HumanVerificationRecord
from soc_agent.review.authorization import HumanPermission
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now

REVIEW_VERSION = "soc-human-improvement-review:v1"


class ReviewDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    DEFER = "DEFER"


class BlockingReason(StrEnum):
    VARIANT_NOT_CONSTRUCTIBLE = "VARIANT_NOT_CONSTRUCTIBLE"
    BASELINE_UNAVAILABLE = "BASELINE_UNAVAILABLE"
    NO_EXECUTED_COMPARISON = "NO_EXECUTED_COMPARISON"
    NO_MEASURABLE_RESULT = "NO_MEASURABLE_RESULT"
    SAFETY_FAIL = "SAFETY_FAIL"
    SAFETY_UNKNOWN = "SAFETY_UNKNOWN"
    ACCEPTANCE_FAIL = "ACCEPTANCE_FAIL"
    ACCEPTANCE_UNKNOWN = "ACCEPTANCE_UNKNOWN"


class ReasonCode(StrEnum):
    PROMOTION_CONSIDERATION = "PROMOTION_CONSIDERATION"
    UNSUITABLE_PROPOSAL = "UNSUITABLE_PROPOSAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SAFETY_CONCERN = "SAFETY_CONCERN"


class ReviewRequestContent(Frozen):
    review_version: Literal["soc-human-improvement-review:v1"] = REVIEW_VERSION
    binding: EvaluationBinding
    variant: ArtifactReference
    baseline_result: ArtifactReference
    candidate_result: ArtifactReference
    comparison: ArtifactReference
    # This checked advisory proposal is a convenience view, never an instruction.
    candidate: CandidateContent
    summary: ComparisonContent
    limitations: tuple[str, ...]
    reviewability: Literal["REVIEWABLE", "NOT_REVIEWABLE"]
    blocking_reasons: tuple[BlockingReason, ...]
    approval_blockers: tuple[BlockingReason, ...]
    baseline_safety_counts: tuple[int, int, int]
    candidate_safety_counts: tuple[int, int, int]
    authorization_incident: UUID
    required_permission: Literal[HumanPermission.REVIEW_IMPROVEMENT_CANDIDATE] = (
        HumanPermission.REVIEW_IMPROVEMENT_CANDIDATE
    )
    confirmation_purpose: Literal["improvement_review_decision"] = "improvement_review_decision"
    authority: Literal["HUMAN_IMPROVEMENT_REVIEW_REQUEST_NOT_AUTHORIZATION"] = (
        "HUMAN_IMPROVEMENT_REVIEW_REQUEST_NOT_AUTHORIZATION"
    )

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if (
            content_digest(self.candidate) != self.binding.source.candidate.identity
            or content_digest(self.candidate) != self.binding.source.candidate.digest
            or self.summary.binding != self.binding
            or self.summary.baseline_result != self.baseline_result
            or self.summary.candidate_result != self.candidate_result
            or content_digest(self.summary) != self.comparison.digest
            or (self.reviewability == "NOT_REVIEWABLE") != bool(self.blocking_reasons)
        ):
            raise ValueError("Review source binding mismatch")
        return self


class ImprovementReviewRequest(Frozen):
    review_request_id: Hash
    content: ReviewRequestContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.review_request_id != content_digest(self.content):
            raise ValueError("Review request identity mismatch")
        return self


class ReviewSubmission(Frozen):
    review_request: ArtifactReference
    decision: ReviewDecision
    reason: ReasonCode
    note: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def annotation(self) -> Self:
        if any(ord(c) < 32 and c not in "\n\t" for c in self.note) or re.search(
            r"(?i)(password|passwd|secret|token|credential|api[_ -]?key)\s*[:=]"
            r"|\bbearer\s+\S+|-----BEGIN.*PRIVATE KEY-----",
            self.note,
        ):
            raise ValueError("Notes must be plain text without authentication material")
        expected = {
            ReviewDecision.APPROVE: {ReasonCode.PROMOTION_CONSIDERATION},
            ReviewDecision.REJECT: {ReasonCode.UNSUITABLE_PROPOSAL, ReasonCode.SAFETY_CONCERN},
            ReviewDecision.DEFER: {ReasonCode.INSUFFICIENT_EVIDENCE, ReasonCode.SAFETY_CONCERN},
        }
        if self.reason not in expected[self.decision]:
            raise ValueError("Decision/reason mismatch")
        return self

    @property
    def digest(self) -> str:
        return content_digest(self)


class ImprovementReviewRecord(Frozen):
    review_record_id: Hash
    review_version: Literal["soc-human-improvement-review:v1"] = REVIEW_VERSION
    submission: ReviewSubmission
    snapshot: ReviewRequestContent
    verification: HumanVerificationRecord
    authority: Literal["PROMOTION_CONSIDERATION_ONLY"] = "PROMOTION_CONSIDERATION_ONLY"
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def binding(self) -> Self:
        from soc_agent.improvement_review.service import review_context

        request = ImprovementReviewRequest(
            review_request_id=content_digest(self.snapshot), content=self.snapshot
        )
        v = self.verification
        if (
            self.submission.review_request.identity != request.review_request_id
            or self.submission.review_request.digest != content_digest(request.content)
            or v.context != review_context(request, self.submission)
            or v.permission != HumanPermission.REVIEW_IMPROVEMENT_CANDIDATE
            or self.review_record_id != record_identity(self.submission, v)
        ):
            raise ValueError("Human improvement review binding mismatch")
        require_decision(request, self.submission.decision)
        return self


class RecordIdentity(Frozen):
    submission: ReviewSubmission
    provider: str
    subject: str
    session: str


def record_identity(submission: ReviewSubmission, verification: HumanVerificationRecord) -> str:
    return content_digest(
        RecordIdentity(
            submission=submission,
            provider=verification.provider_id,
            subject=verification.subject_id,
            session=verification.session_id,
        )
    )


def require_decision(request: ImprovementReviewRequest, decision: ReviewDecision) -> None:
    """Facts never self-approve. FAIL and UNKNOWN both block progression in v1."""
    from soc_agent.review.errors import HumanAuthorizationDenied

    if decision == ReviewDecision.APPROVE and (
        request.content.reviewability != "REVIEWABLE"
        or request.content.blocking_reasons
        or request.content.approval_blockers
        or any(
            s != VerdictState.PASS
            for i in request.content.summary.safety
            for s in (i.baseline, i.candidate)
        )
        or any(c.status != VerdictState.PASS for c in request.content.summary.acceptance)
    ):
        raise HumanAuthorizationDenied("APPROVE requires reviewable evidence with no blockers")


def safety_counts(values: tuple[VerdictState, ...]) -> tuple[int, int, int]:
    return (
        values.count(VerdictState.PASS),
        values.count(VerdictState.FAIL),
        values.count(VerdictState.UNKNOWN),
    )
