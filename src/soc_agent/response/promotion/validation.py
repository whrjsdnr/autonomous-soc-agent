"""Authoritative current checks; no regeneration of advisory artifacts."""

import json

from soc_agent._json import canonical_json_object
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.response.advisory import ResponsePlan
from soc_agent.response.advisory.source import PersistentPlanningSource
from soc_agent.response.promotion.errors import (
    IncidentClosed,
    InputSchemaChanged,
    InvalidPromotionArtifact,
    PromotionInputInvalid,
    PromotionPolicyChanged,
    PromotionPolicyDenied,
    PromotionToolMissing,
    ToolMetadataChanged,
)
from soc_agent.response.promotion.models import PromotionTarget
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.validation import validate_decision
from soc_agent.state import IncidentStatus
from soc_agent.tools import ToolRegistry


class CurrentValidation:
    def __init__(self, store: SQLiteGovernanceStore, registry: ToolRegistry, policy: PolicyEngine):
        self.store, self.registry, self.policy = store, registry, policy

    def sources(self, plan: ResponsePlan) -> None:
        basis = plan.content.basis
        current = self.store.load(basis.incident_id)
        if current.state.status == IncidentStatus.CLOSED:
            raise IncidentClosed("CLOSED incidents cannot be promoted or executed")
        if current.anchor != basis.snapshot:
            raise StaleSnapshotError(
                "Incident revision/fingerprint changed; new planning/review required"
            )
        validate_decision(current.state, basis.decision)
        PersistentPlanningSource(self.store).validate_sources(
            current.state, basis.decision, basis.review
        )

    def check(self, plan: ResponsePlan, target: PromotionTarget) -> PolicyResult:
        self.sources(plan)
        if (
            plan.plan_id != target.response_plan_id
            or plan.content.basis.snapshot != target.snapshot
            or target.proposal not in plan.proposed_actions
        ):
            raise InvalidPromotionArtifact("Proposal does not belong to this source plan")
        details = target.proposal.details
        if details.intent.candidate_tool not in self.registry:
            raise PromotionToolMissing("Registered tool was removed")
        tool = self.registry.get(details.intent.candidate_tool)
        if tool.metadata != details.metadata:
            raise ToolMetadataChanged("Tool metadata changed; new planning/review required")
        if canonical_json_object(tool.input_model.model_json_schema()) != details.input_schema_json:
            raise InputSchemaChanged("Input schema changed; new planning/review required")
        try:
            value = tool.input_model.model_validate(
                json.loads(details.intent.proposed_input), extra="forbid"
            )
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            tool.input_model.model_validate(payload, extra="forbid")
            if canonical_json_object(payload) != details.intent.proposed_input:
                raise ValueError("Input normalization would change the reviewed input")
        except (ValueError, TypeError) as error:
            raise PromotionInputInvalid("Exact reviewed input no longer validates") from error
        current = PolicyResult.model_validate(self.policy.evaluate(tool.metadata).model_dump())
        floor = PolicyEngine().evaluate(tool.metadata)
        if current.decision == PolicyDecision.DENY or floor.decision == PolicyDecision.DENY:
            raise PromotionPolicyDenied("Current policy denies promotion/execution")
        if (
            floor.decision == PolicyDecision.REQUIRE_APPROVAL
            and current.decision == PolicyDecision.ALLOW
        ):
            raise PromotionPolicyChanged(
                "Current policy cannot weaken existing approval requirements"
            )
        return current
