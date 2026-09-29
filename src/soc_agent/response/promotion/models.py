"""Promotion is a provenance artifact, never a Tool Approval or execution command."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from soc_agent.policy import PolicyResult
from soc_agent.response.advisory.models import ActionProposal
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash, StateAnchor, Subject, Text
from soc_agent.state.evidence import UTCTimestamp, utc_now


class ReviewDisposition(StrEnum):
    READY_FOR_PROMOTION = "ready_for_promotion"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class BlockerResponse(Frozen):
    blocking_reason: Text
    resolution: Literal["addressed_for_promotion", "unresolved"]
    response: Text


class PromotionTarget(Frozen):
    incident_id: UUID
    response_plan_id: Hash
    proposal: ActionProposal
    proposal_digest: Hash
    snapshot: StateAnchor

    @model_validator(mode="after")
    def binding(self) -> Self:
        if (
            self.incident_id != self.snapshot.incident_id
            or self.incident_id != self.proposal.incident_id
            or self.response_plan_id != self.proposal.response_plan_id
            or self.proposal_digest != content_digest(self.proposal)
        ):
            raise ValueError("Response target binding mismatch")
        return self


class ResponseReviewIntent(Frozen):
    intent_id: UUID = Field(default_factory=uuid4)
    target: PromotionTarget
    reviewer_id: Subject
    disposition: ReviewDisposition
    reason: Text
    blocker_responses: tuple[BlockerResponse, ...] = ()

    @model_validator(mode="after")
    def blockers(self) -> Self:
        if self.disposition == ReviewDisposition.READY_FOR_PROMOTION:
            supplied = [b.blocking_reason for b in self.blocker_responses]
            expected = self.target.proposal.details.blocking_reasons
            if any(b.resolution != "addressed_for_promotion" for b in self.blocker_responses):
                raise ValueError("Unresolved blocker prevents readiness for promotion")
            if len(supplied) != len(set(supplied)) or set(supplied) != set(expected):
                raise ValueError("Human must address every recorded planning blocker")
        return self


class ResponseActionReview(Frozen):
    review_id: UUID = Field(default_factory=uuid4)
    intent: ResponseReviewIntent
    created_at: UTCTimestamp = Field(default_factory=utc_now)


class PromotionRequest(Frozen):
    request_id: UUID = Field(default_factory=uuid4)
    review: ResponseActionReview
    target: PromotionTarget

    @model_validator(mode="after")
    def binding(self) -> Self:
        if self.review.intent.target != self.target:
            raise ValueError("Promotion request differs from reviewed target")
        return self


class PromotionContent(Frozen):
    request: PromotionRequest
    current_snapshot: StateAnchor
    current_policy: PolicyResult
    promotion_rule_version: Literal["response-promotion:v1"] = "response-promotion:v1"


class PromotedAction(Frozen):
    kind: Literal["promoted_response_action"] = "promoted_response_action"
    promoted_id: Hash
    content: PromotionContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.promoted_id != content_digest(self.content):
            raise ValueError("Promoted identity mismatch")
        if self.content.current_snapshot != self.content.request.target.snapshot:
            raise ValueError("Promoted snapshot mismatch")
        return self


class ExecutionProvenance(Frozen):
    event_id: UUID = Field(default_factory=uuid4)
    promoted_id: Hash
    incident_id: UUID
    response_plan_id: Hash
    proposal_id: Hash
    response_review_id: UUID
    promotion_request_id: UUID
    action_id: UUID
    approval_id: UUID | None
    snapshot: StateAnchor
    outcome: Literal["started", "succeeded", "rejected", "failed", "outcome_unknown"]
    error_type: str | None = None
    occurred_at: UTCTimestamp = Field(default_factory=utc_now)
