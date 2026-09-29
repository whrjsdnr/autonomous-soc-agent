"""Explicit human review and promotion. No ApprovalManager or Executor dependency."""

from threading import RLock
from uuid import UUID

from pydantic import BaseModel

from soc_agent.policy import PolicyEngine
from soc_agent.response.advisory import ResponsePlan
from soc_agent.response.promotion.errors import (
    InvalidPromotionArtifact,
    PromotionPolicyChanged,
    ResponseChangesRequested,
    ResponseReviewRejected,
)
from soc_agent.response.promotion.models import (
    BlockerResponse,
    PromotedAction,
    PromotionContent,
    PromotionRequest,
    PromotionTarget,
    ResponseActionReview,
    ResponseReviewIntent,
    ReviewDisposition,
)
from soc_agent.response.promotion.validation import CurrentValidation
from soc_agent.review.authority import (
    DenyHumanAuthority,
    HumanAction,
    HumanAuthority,
    VerifiedHumanAction,
)
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.validation import checked
from soc_agent.tools import ToolRegistry


def exact[T: BaseModel](model: type[T], value: T) -> T:
    try:
        return checked(model, value)
    except (ValueError, TypeError, AttributeError) as error:
        raise InvalidPromotionArtifact(f"Invalid {model.__name__}") from error


def confirm(authority: HumanAuthority, credential: str, action: HumanAction, digest: str) -> str:
    proof = checked(
        VerifiedHumanAction,
        authority.verify(credential=credential, action=action, binding_digest=digest),
    )
    if proof.action != action or proof.binding_digest != digest:
        raise HumanAuthorizationDenied("Human confirmation purpose/binding mismatch")
    return proof.subject_id


class PromotionService:
    def __init__(
        self,
        *,
        store: SQLiteGovernanceStore,
        registry: ToolRegistry,
        policy: PolicyEngine,
        authority: HumanAuthority | None = None,
    ) -> None:
        self.validation = CurrentValidation(store, registry, policy)
        self._authority = authority if authority is not None else DenyHumanAuthority()
        self._lock = RLock()
        self._plans: dict[str, ResponsePlan] = {}
        self._intents: dict[UUID, ResponseReviewIntent] = {}
        self._reviews: dict[UUID, ResponseActionReview] = {}
        self._requests: dict[UUID, PromotionRequest] = {}
        self._promoted: dict[str, PromotedAction] = {}

    def request_review(
        self,
        plan: ResponsePlan,
        proposal_id: str,
        *,
        reviewer_id: str,
        disposition: ReviewDisposition,
        reason: str,
        blocker_responses: tuple[BlockerResponse, ...] = (),
    ) -> ResponseReviewIntent:
        plan = exact(ResponsePlan, plan)
        self.validation.sources(plan)
        proposal = next((a for a in plan.proposed_actions if a.proposal_id == proposal_id), None)
        if proposal is None:
            raise InvalidPromotionArtifact("Proposal not found in plan")
        target = PromotionTarget(
            incident_id=proposal.incident_id,
            response_plan_id=plan.plan_id,
            proposal=proposal,
            proposal_digest=content_digest(proposal),
            snapshot=plan.content.basis.snapshot,
        )
        intent = ResponseReviewIntent(
            target=target,
            reviewer_id=reviewer_id,
            disposition=disposition,
            reason=reason,
            blocker_responses=blocker_responses,
        )
        with self._lock:
            old = self._plans.get(plan.plan_id)
            if old is not None and old.content != plan.content:
                raise InvalidPromotionArtifact("Plan identity collision")
            self._plans[plan.plan_id] = plan
            self._intents[intent.intent_id] = intent
        return intent

    def record_review(
        self, intent: ResponseReviewIntent, *, credential: str
    ) -> ResponseActionReview:
        intent = exact(ResponseReviewIntent, intent)
        with self._lock:
            if self._intents.get(intent.intent_id) != intent:
                raise InvalidPromotionArtifact("Unknown or changed response review intent")
            actor = confirm(
                self._authority,
                credential,
                HumanAction.REVIEW_RESPONSE_ACTION,
                content_digest(intent),
            )
            if actor != intent.reviewer_id:
                raise HumanAuthorizationDenied("Reviewer differs from authenticated human")
            self.validation.sources(self._plans[intent.target.response_plan_id])
            if any(r.intent.intent_id == intent.intent_id for r in self._reviews.values()):
                raise InvalidPromotionArtifact("Review intent already recorded")
            result = ResponseActionReview(intent=intent)
            self._reviews[result.review_id] = result
            return result

    def request_promotion(self, review: ResponseActionReview) -> PromotionRequest:
        review = exact(ResponseActionReview, review)
        with self._lock:
            if self._reviews.get(review.review_id) != review:
                raise InvalidPromotionArtifact("Unknown or changed response review")
            if review.intent.disposition == ReviewDisposition.REJECT:
                raise ResponseReviewRejected("Human rejected promotion")
            if review.intent.disposition == ReviewDisposition.REQUEST_CHANGES:
                raise ResponseChangesRequested("Human requires changes before promotion")
            request = PromotionRequest(review=review, target=review.intent.target)
            self._requests[request.request_id] = request
            return request

    def promote(self, request: PromotionRequest) -> PromotedAction:
        request = exact(PromotionRequest, request)
        with self._lock:
            if self._requests.get(request.request_id) != request:
                raise InvalidPromotionArtifact("Unknown or changed promotion request")
            policy = self.validation.check(
                self._plans[request.target.response_plan_id], request.target
            )
            content = PromotionContent(
                request=request, current_snapshot=request.target.snapshot, current_policy=policy
            )
            identity = content_digest(content)
            if identity not in self._promoted:
                self._promoted[identity] = PromotedAction(promoted_id=identity, content=content)
            return self._promoted[identity]

    def validate_promoted(self, promoted: PromotedAction) -> PromotedAction:
        promoted = exact(PromotedAction, promoted)
        with self._lock:
            if self._promoted.get(promoted.promoted_id) != promoted:
                raise InvalidPromotionArtifact("Unregistered or changed promotion")
            request = promoted.content.request
            current = self.validation.check(
                self._plans[request.target.response_plan_id], request.target
            )
            if current != promoted.content.current_policy:
                raise PromotionPolicyChanged(
                    "Policy changed after promotion; no automatic re-promotion"
                )
        return promoted

    def reviews(self) -> tuple[ResponseActionReview, ...]:
        with self._lock:
            return tuple(self._reviews.values())

    def source_plan(self, promoted: PromotedAction) -> ResponsePlan:
        """Export only a currently validated, registered promotion's source lineage."""
        promoted = self.validate_promoted(promoted)
        with self._lock:
            return self._plans[promoted.content.request.target.response_plan_id]

    def requests(self) -> tuple[PromotionRequest, ...]:
        with self._lock:
            return tuple(self._requests.values())

    def promoted_actions(self) -> tuple[PromotedAction, ...]:
        with self._lock:
            return tuple(self._promoted.values())
