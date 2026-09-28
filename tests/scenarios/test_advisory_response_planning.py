"""Real saved ML inference; Mock LLM and separate test-only human confirmation.

Registered fixture tools are never executed. The pipeline ends at advisory preflight.
"""

import pytest
from tests.review_support import HumanConfirmations, record_review
from tests.scenarios.test_governed_decision_application import packages as packages
from tests.scenarios.test_security_ai_fusion import fuse, inputs_for, network_features
from tests.unit.execution.conftest import make_tool

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyDecision
from soc_agent.response.advisory import (
    CandidateIntent,
    PersistentPlanningSource,
    ResponsePlan,
    ResponsePlanner,
)
from soc_agent.review import ReviewOutcome
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.security_ai.fusion import MultiModelFusionEngine
from soc_agent.security_ai.packaging.package import ModelPackage
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolPermission, ToolRegistry, ToolRiskLevel


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "evidence",
        "model_only",
        "investigate",
        "rejected",
        "unavailable",
        "write",
        "deny",
        "tamper",
        "disagreement",
    ],
)
async def test_real_pipeline_to_advisory_preflight(packages, tmp_path, monkeypatch, scenario):
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="synthetic",
            summary="Source telemetry, not proof of compromise",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    features = network_features(anomaly_without_attribution=scenario == "disagreement")
    inputs = await inputs_for(
        packages, state, {"network_classifier": features, "network_anomaly": features}
    )
    fusion = fuse(packages, state, inputs)
    expected = {"BENIGN", "anomaly"} if scenario == "disagreement" else {"BruteForce", "anomaly"}
    assert {c.decision for c in fusion.contributions} == expected
    llm = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info" if scenario == "model_only" else "high",
                    "confidence": 0.2,
                    "summary": "Unverified advisory interpretation",
                    "supporting_evidence_ids": [str(e.evidence_id) for e in state.evidence],
                },
            }
        ]
    )
    assessment = await ThreatAssessor(llm_client=llm).assess(state, fusion_result=fusion)
    decision = IncidentDecisionEngine().decide(
        state, assessment.threat_assessment, fusion_assessment=assessment
    )
    store = SQLiteGovernanceStore.create(tmp_path / "planning.sqlite")
    store.register(state)
    authority = HumanConfirmations()
    service = PersistentHumanReviewService(store=store, authority=authority)
    outcome = {"investigate": ReviewOutcome.INVESTIGATE, "rejected": ReviewOutcome.REJECTED}.get(
        scenario, ReviewOutcome.ACKNOWLEDGED
    )
    review = record_review(service, authority, service.request_review(state, decision), outcome)
    registry = ToolRegistry()
    read_tool = make_tool(ToolPermission.NETWORK_READ, ToolRiskLevel.READ_ONLY, "inspect_records")
    registry.register(read_tool.tool)
    if scenario != "unavailable":
        registry.register(
            make_tool(
                ToolPermission.NETWORK_WRITE,
                ToolRiskLevel.DESTRUCTIVE if scenario == "deny" else ToolRiskLevel.HIGH,
                "fixture_response",
            ).tool
        )
    planner = ResponsePlanner(registry=registry, source=PersistentPlanningSource(store))
    candidate = CandidateIntent(
        candidate_tool="inspect_records",
        proposed_input={"target": "host_a"},
        purpose="Consider targeted inspection",
        rationale="Unverified analyst draft",
        evidence_ids=()
        if scenario == "model_only"
        else tuple(e.evidence_id for e in state.evidence),
    )
    candidates = (
        (candidate,)
        if scenario == "unavailable"
        else (candidate, candidate.model_copy(update={"candidate_tool": "fixture_response"}))
    )
    before = state.model_dump_json(), store.load(state.incident_id), store.events(), registry.list()

    def forbidden(*args, **kwargs):
        pytest.fail("Advisory planner attempted inference, approval, execution or state mutation")

    for cls, method in (
        (Tool, "execute"),
        (GovernedExecutor, "execute"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (ToolRegistry, "register"),
        (PersistentHumanReviewService, "authorize_change"),
        (PersistentHumanReviewService, "apply"),
        (GovernanceSession, "save_state"),
        (SQLiteGovernanceStore, "compare_and_apply"),
        (IncidentDecisionEngine, "decide"),
        (ThreatAssessor, "assess"),
        (ModelPackage, "predict"),
        (MultiModelFusionEngine, "fuse"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    plan = planner.create_plan(
        incident_state=state,
        decision=decision,
        review=review,
        objective="Consider human-reviewed options",
        candidates=candidates,
    )
    assert plan.content.basis.decision.model_derived_context == fusion
    assert fusion.confidence_state == "unknown"
    assert plan.content.evidence_ids == tuple(e.evidence_id for e in state.evidence)
    assert plan.content.basis.decision.assessment == decision.assessment
    assert plan.content.basis.review == review
    if scenario == "rejected":
        assert plan.proposed_actions == ()
    elif scenario in ("model_only", "investigate", "unavailable"):
        assert len(plan.proposed_actions) == 1
        assert plan.proposed_actions[0].details.category == "additional_investigation"
    else:
        response = next(
            a for a in plan.proposed_actions if a.details.category == "response_consideration"
        )
        assert response.details.policy_preflight.decision == (
            PolicyDecision.DENY if scenario == "deny" else PolicyDecision.REQUIRE_APPROVAL
        )
        assert response.details.reversibility == "unknown"
        assert response.details.blocking_reasons
    if scenario == "model_only":
        assert "model_alert_requires_grounding" in plan.content.dispositions
        assert plan.content.basis.evidence == state.evidence
        assert plan.proposed_actions[0].details.intent.evidence_ids == ()
        assert any(
            "no linked Evidence" in reason
            for reason in plan.proposed_actions[0].details.blocking_reasons
        )
        assert plan.content.investigation_gaps
        for invalid_id in (fusion.fusion_id, inputs[0].signal.signal_id):
            with pytest.raises(ValueError):
                planner.create_plan(
                    incident_state=state,
                    decision=decision,
                    review=review,
                    objective="Invalid model ID reference",
                    candidates=(candidate.model_copy(update={"evidence_ids": (invalid_id,)}),),
                )
    if scenario == "disagreement":
        assert "assessment_model_disagreement_requires_review" in plan.content.dispositions
    if scenario == "tamper":
        tampered = plan.model_dump()
        tampered["proposed_actions"][0]["details"]["intent"]["proposed_input"] = (
            '{"target":"other"}'
        )
        with pytest.raises(ValueError):
            ResponsePlan.model_validate(tampered)
    planner.validate_current(plan, incident_state=state)
    assert before == (
        state.model_dump_json(),
        store.load(state.incident_id),
        store.events(),
        registry.list(),
    )
    assert service.authorizations() == store.applications() == ()
    assert llm.call_count == 1
    assert read_tool.call_count == 0
