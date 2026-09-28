"""Synchronous deterministic planning: registered tools and explicit untrusted intents only."""

import json

from soc_agent._json import canonical_json_object
from soc_agent.decision import IncidentDecision
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.response.advisory.models import (
    ActionDetails,
    ActionProposal,
    CandidateIntent,
    PlanContent,
    PlanningBasis,
    ProposalCategory,
    ProposalContent,
    ResponsePlan,
    ToolBinding,
)
from soc_agent.response.advisory.rules import defer_response, dispositions, is_investigation
from soc_agent.response.advisory.source import PlanningSource
from soc_agent.review.identity import content_digest, state_fingerprint
from soc_agent.review.models import HumanReviewRecord, ReviewOutcome
from soc_agent.review.validation import checked, validate_decision
from soc_agent.state import IncidentState, IncidentStatus
from soc_agent.tools import ToolRegistry


class ResponsePlanner:
    def __init__(self, *, registry: ToolRegistry, source: PlanningSource) -> None:
        self._registry = registry
        self._source = source

    def create_plan(
        self,
        *,
        incident_state: IncidentState,
        decision: IncidentDecision,
        review: HumanReviewRecord,
        objective: str,
        candidates: tuple[CandidateIntent, ...] = (),
    ) -> ResponsePlan:
        state = checked(IncidentState, incident_state)
        decision = checked(IncidentDecision, decision)
        review = checked(HumanReviewRecord, review)
        validate_decision(state, decision)
        if state.status == IncidentStatus.CLOSED:
            raise ValueError("CLOSED incident requires a separate reconsideration workflow")
        anchor = self._source.validate_sources(state, decision, review)
        if anchor.fingerprint != state_fingerprint(state):
            raise ValueError("Source snapshot fingerprint mismatch")
        basis = PlanningBasis(
            incident_id=state.incident_id,
            snapshot=anchor,
            decision=decision,
            review=review,
            evidence=tuple(sorted(state.evidence, key=lambda e: str(e.evidence_id))),
        )
        known = {e.evidence_id for e in state.evidence}
        tools = {m.name: self._registry.get(m.name) for m in self._registry.list()}
        notes = list(dispositions(decision, review))
        if not any(not is_investigation(t.metadata) for t in tools.values()):
            notes.append("appropriate_response_tool_unavailable")
        if not candidates:
            notes.append("no_candidate_intents_supplied")
        validated_candidates = {
            content_digest(c): c for c in (checked(CandidateIntent, value) for value in candidates)
        }
        candidates = tuple(validated_candidates[k] for k in sorted(validated_candidates))
        actions = []
        for candidate in candidates:
            if candidate.candidate_tool not in tools:
                raise ValueError("Candidate tool does not exist in the Registry")
            if not set(candidate.evidence_ids) <= known:
                raise ValueError("Candidate Evidence does not exist in current Incident")
            tool = tools[candidate.candidate_tool]
            # Same strict-extra validation and JSON round trip as the existing response validator.
            value = tool.input_model.model_validate(
                json.loads(candidate.proposed_input), extra="forbid"
            )
            payload = value.model_dump(mode="json", by_alias=True, round_trip=True)
            tool.input_model.model_validate(payload, extra="forbid")
            candidate = CandidateIntent.model_validate(
                candidate.model_dump() | {"proposed_input": payload}
            )
            investigation = is_investigation(tool.metadata)
            if review.outcome == ReviewOutcome.REJECTED:
                continue
            if not investigation and defer_response(decision, review):
                notes.append("response_candidate_deferred_for_investigation")
                continue
            policy = PolicyEngine().evaluate(tool.metadata)
            binding = ToolBinding(
                metadata=tool.metadata,
                input_schema=canonical_json_object(tool.input_model.model_json_schema()),
            )
            blocks = ["Response plan human review and explicit future promotion are required."]
            if policy.decision != PolicyDecision.ALLOW:
                blocks.append(policy.reason)
            if decision.additional_investigation_required:
                blocks.append("Resolve the recorded investigation gaps before response promotion.")
            if not candidate.evidence_ids:
                blocks.append(
                    "Candidate has no linked Evidence; establish its factual and target basis."
                )
            actions.append(
                ActionDetails(
                    intent=candidate,
                    category=ProposalCategory.INVESTIGATION
                    if investigation
                    else ProposalCategory.RESPONSE,
                    metadata=binding.metadata,
                    input_schema_json=binding.input_schema,
                    tool_binding=content_digest(binding),
                    policy_preflight=policy,
                    human_approval_required=policy.decision == PolicyDecision.REQUIRE_APPROVAL,
                    expected_security_effect=(
                        "Intended purpose is unverified; security efficacy is unknown."
                    ),
                    expected_operational_impact=(
                        "Read operations may expose sensitive data and consume system resources."
                        if investigation
                        else "Writes may disrupt users, traffic or services; impact is unverified.",
                    ),
                    blocking_reasons=tuple(blocks),
                    uncertainties=(
                        "Schema validity does not prove the target is supported by Evidence.",
                        "Metadata does not establish reversibility or operational impact.",
                        "Revalidate state, review, tool binding and Policy before promotion.",
                    ),
                )
            )
        # Candidates are an unordered set of alternatives, not an executable sequence.
        alternatives = {content_digest(action): action for action in actions}
        actions = tuple(alternatives[key] for key in sorted(alternatives))
        evidence_ids = set(decision.evidence_ids)
        for action in actions:
            evidence_ids.update(action.intent.evidence_ids)
        content = PlanContent(
            basis=basis,
            objective=objective,
            rationale=decision.rationale,
            uncertainties=(*decision.uncertainties, *decision.limitations),
            evidence_ids=tuple(sorted(evidence_ids, key=str)),
            candidate_intents=candidates,
            action_details=actions,
            investigation_gaps=decision.investigation_reasons,
            human_review_requirements=(
                "Review purpose, target grounding, operational impact and all uncertainties.",
                "Incident review and state authorization are not Tool execution approval.",
                "Policy preflight is not execution authorization.",
            ),
            residual_risk_without_action=(
                "Unresolved concerns remain; likelihood and damage are unknown."
            ),
            dispositions=tuple(sorted(set(notes))),
        )
        plan_id = content_digest(content)
        proposals = []
        for details in actions:
            proposal = ProposalContent(
                incident_id=state.incident_id, response_plan_id=plan_id, details=details
            )
            proposals.append(
                ActionProposal(proposal_id=content_digest(proposal), **proposal.model_dump())
            )
        return ResponsePlan(plan_id=plan_id, content=content, proposed_actions=tuple(proposals))

    def validate_current(self, plan: ResponsePlan, *, incident_state: IncidentState) -> None:
        """Read-only stale check, not approval, persistence or execution promotion."""
        plan = checked(ResponsePlan, plan)
        basis = plan.content.basis
        fresh = self.create_plan(
            incident_state=incident_state,
            decision=basis.decision,
            review=basis.review,
            objective=plan.content.objective,
            candidates=plan.content.candidate_intents,
        )
        if fresh.plan_id != plan.plan_id:
            raise ValueError("Stale or inconsistent advisory proposal")
