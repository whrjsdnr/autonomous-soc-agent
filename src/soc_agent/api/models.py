"""Strict transport requests. Credentials and authority objects are never body fields."""

from uuid import UUID

from pydantic import Field

from soc_agent.investigation.runtime.models import WorkflowResult
from soc_agent.response.advisory import CandidateIntent
from soc_agent.response.promotion import BlockerResponse, ReviewDisposition
from soc_agent.review.models import Frozen, Hash, ReviewOutcome, Subject


class Empty(Frozen):
    pass


class CreateIncident(Frozen):
    incident_id: UUID


class StepRequest(Frozen):
    run_id: UUID
    expected_revision: int = Field(strict=True, ge=0)
    review_id: UUID | None = None
    promoted_id: Hash | None = None
    approval_id: UUID | None = None
    candidates: tuple[CandidateIntent, ...] = ()
    execute: bool = Field(default=False, strict=True)


class IncidentReview(Frozen):
    request_id: UUID
    reviewer_id: Subject
    outcome: ReviewOutcome
    reason: str = Field(min_length=1, max_length=4000)


class ResponseReviewDraft(Frozen):
    proposal_id: Hash
    reviewer_id: Subject
    disposition: ReviewDisposition
    reason: str = Field(min_length=1, max_length=4000)
    blocker_responses: tuple[BlockerResponse, ...] = ()


class ResponseReview(Frozen):
    intent_id: UUID


class Promotion(Frozen):
    review_id: UUID


class ApprovalDraft(Frozen):
    promoted_id: Hash
    reason: str = Field(min_length=1, max_length=4000)


class Approval(Frozen):
    promoted_id: Hash
    approval_id: UUID


class WorkflowView(WorkflowResult):
    workflow_id: UUID
    checkpoint_revision: int = Field(strict=True, ge=0)
