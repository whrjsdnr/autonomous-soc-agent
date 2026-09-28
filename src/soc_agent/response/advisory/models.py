"""Advisory-only artifacts deliberately incompatible with execution.ActionProposal."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from soc_agent._json import canonical_json_object
from soc_agent.decision import IncidentDecision
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.response.advisory.rules import defer_response, is_investigation
from soc_agent.review.identity import content_digest
from soc_agent.review.models import (
    Frozen,
    Hash,
    HumanReviewRecord,
    ReviewOutcome,
    StateAnchor,
    Text,
)
from soc_agent.state import Evidence
from soc_agent.state.evidence import UTCTimestamp, utc_now
from soc_agent.tools import ToolMetadata
from soc_agent.tools.models import ToolName


class ProposalCategory(StrEnum):
    INVESTIGATION = "additional_investigation"
    RESPONSE = "response_consideration"


class CandidateIntent(Frozen):
    """Untrusted explicit draft; cannot specify permission, risk or policy decisions."""

    candidate_tool: ToolName
    proposed_input: str
    purpose: Text
    rationale: Text
    evidence_ids: tuple[UUID, ...] = ()

    @field_validator("proposed_input", mode="before")
    @classmethod
    def canonical_input(cls, value: object) -> str:
        return canonical_json_object(value)

    @field_validator("evidence_ids")
    @classmethod
    def canonical_evidence(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        return tuple(sorted(set(value), key=str))


class PlanningBasis(Frozen):
    incident_id: UUID
    snapshot: StateAnchor
    decision: IncidentDecision
    review: HumanReviewRecord
    evidence: tuple[Evidence, ...]

    @model_validator(mode="after")
    def bindings(self) -> Self:
        target = self.review.target
        if (
            self.incident_id != self.snapshot.incident_id
            or self.decision.incident_id != self.incident_id
            or target.snapshot != self.snapshot
            or target.decision_id != self.decision.decision_id
            or target.decision_digest != content_digest(self.decision)
            or target.decision_version != self.decision.decision_version
            or target.decision_rule_version != self.decision.rule_version
            or any(e.incident_id != self.incident_id for e in self.evidence)
            or len({e.evidence_id for e in self.evidence}) != len(self.evidence)
        ):
            raise ValueError("Response planning source binding mismatch")
        return self


class ActionDetails(Frozen):
    intent: CandidateIntent
    category: ProposalCategory
    metadata: ToolMetadata
    input_schema_json: str
    tool_binding: Hash
    policy_preflight: PolicyResult
    human_approval_required: bool
    expected_security_effect: Text
    expected_operational_impact: tuple[Text, ...]
    reversibility: Literal["unknown"] = "unknown"
    blocking_reasons: tuple[Text, ...]
    uncertainties: tuple[Text, ...]
    semantic_claim_origin: Literal["unverified_candidate_intent"] = "unverified_candidate_intent"

    @model_validator(mode="after")
    def metadata_and_policy(self) -> Self:
        binding = content_digest(
            ToolBinding(metadata=self.metadata, input_schema=self.input_schema_json)
        )
        policy = PolicyEngine().evaluate(self.metadata)
        if (
            self.category
            != (
                ProposalCategory.INVESTIGATION
                if is_investigation(self.metadata)
                else ProposalCategory.RESPONSE
            )
            or self.intent.candidate_tool != self.metadata.name
            or self.tool_binding != binding
            or self.policy_preflight != policy
            or self.human_approval_required != (policy.decision == PolicyDecision.REQUIRE_APPROVAL)
        ):
            raise ValueError("Proposal metadata/policy binding mismatch")
        return self


class ToolBinding(Frozen):
    metadata: ToolMetadata
    input_schema: str


class PlanContent(Frozen):
    basis: PlanningBasis
    objective: Text
    rationale: tuple[Text, ...]
    uncertainties: tuple[Text, ...]
    evidence_ids: tuple[UUID, ...]
    candidate_intents: tuple[CandidateIntent, ...]
    action_details: tuple[ActionDetails, ...]
    investigation_gaps: tuple[Text, ...]
    human_review_requirements: tuple[Text, ...]
    residual_risk_without_action: Text
    dispositions: tuple[Text, ...]
    planning_rule_version: Literal["response-planning:v1"] = "response-planning:v1"

    @model_validator(mode="after")
    def grounding(self) -> Self:
        known = {e.evidence_id for e in self.basis.evidence}
        if any(not set(c.evidence_ids) <= known for c in self.candidate_intents):
            raise ValueError("Candidate Evidence does not belong to the source basis")
        if self.basis.review.outcome == ReviewOutcome.REJECTED and self.action_details:
            raise ValueError("Rejected review cannot ground advisory proposals")
        referenced = set(self.basis.decision.evidence_ids)
        for action in self.action_details:
            if action.category == ProposalCategory.RESPONSE and defer_response(
                self.basis.decision, self.basis.review
            ):
                raise ValueError("Response must be deferred for investigation")
            referenced.update(action.intent.evidence_ids)
        if set(self.evidence_ids) != referenced or not referenced <= known:
            raise ValueError("Response Evidence references are not present in its source basis")
        return self


class ActionProposal(Frozen):
    """No action_id, execution request or conversion API exists on this contract."""

    kind: Literal["advisory_response_proposal"] = "advisory_response_proposal"
    proposal_id: Hash
    incident_id: UUID
    response_plan_id: Hash
    details: ActionDetails

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.proposal_id != content_digest(
            ProposalContent(
                incident_id=self.incident_id,
                response_plan_id=self.response_plan_id,
                details=self.details,
            )
        ):
            raise ValueError("Advisory proposal identity mismatch")
        return self


class ProposalContent(Frozen):
    incident_id: UUID
    response_plan_id: Hash
    details: ActionDetails


class ResponsePlan(Frozen):
    kind: Literal["advisory_response_plan"] = "advisory_response_plan"
    plan_id: Hash
    content: PlanContent
    proposed_actions: tuple[ActionProposal, ...]
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.plan_id != content_digest(self.content):
            raise ValueError("Advisory plan identity mismatch")
        if tuple(a.details for a in self.proposed_actions) != self.content.action_details:
            raise ValueError("Proposal set differs from plan content")
        if len({a.proposal_id for a in self.proposed_actions}) != len(self.proposed_actions):
            raise ValueError("Duplicate advisory proposal")
        for action in self.proposed_actions:
            if (action.response_plan_id, action.incident_id) != (
                self.plan_id,
                self.content.basis.incident_id,
            ):
                raise ValueError("Proposal belongs to another response plan")
        return self
