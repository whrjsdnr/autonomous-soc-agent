"""Saved ML packages, Mock LLM, test-only human confirmation and mock tools only."""

import pytest
import pytest_asyncio
from tests.review_support import HumanConfirmations, authorize, record_review
from tests.scenarios.test_governed_decision_application import packages as packages
from tests.scenarios.test_security_ai_fusion import fuse, inputs_for, network_features
from tests.unit.execution.conftest import make_tool
from tests.unit.promotion.conftest import CurrentPolicy, approve, reviewed

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.execution.errors import (
    ActionAlreadyAttemptedError,
    ApprovalBindingError,
    ApprovalRequiredError,
)
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyDecision
from soc_agent.response.advisory import CandidateIntent, PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.response.promotion.errors import PromotionPolicyDenied, ToolMetadataChanged
from soc_agent.review import SeverityChange
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolPermission, ToolRegistry, ToolRiskLevel


@pytest_asyncio.fixture
async def environment(packages, tmp_path):
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="synthetic",
            summary="Synthetic telemetry, not proof of compromise",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    feature = network_features()
    signals = await inputs_for(
        packages, state, {"network_classifier": feature, "network_anomaly": feature}
    )
    fusion = fuse(packages, state, signals)
    assert {c.decision for c in fusion.contributions} == {"BruteForce", "anomaly"}
    llm = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "high",
                    "confidence": 0.2,
                    "summary": "Unverified concern",
                    "supporting_evidence_ids": [str(state.evidence[0].evidence_id)],
                },
            }
        ]
    )
    assessment = await ThreatAssessor(llm_client=llm).assess(state, fusion_result=fusion)
    decision = IncidentDecisionEngine().decide(
        state, assessment.threat_assessment, fusion_assessment=assessment
    )
    authority = HumanConfirmations()
    store = SQLiteGovernanceStore.create(tmp_path / "promotion.sqlite")
    store.register(state)
    incidents = PersistentHumanReviewService(store=store, authority=authority)
    review = record_review(incidents, authority, incidents.request_review(state, decision))
    registry = ToolRegistry()
    read = make_tool(ToolPermission.NETWORK_READ, ToolRiskLevel.READ_ONLY, "inspect_logs")
    write = make_tool(ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH, "test_response")
    registry.register(read.tool)
    registry.register(write.tool)
    planner = ResponsePlanner(registry=registry, source=PersistentPlanningSource(store))
    candidate = CandidateIntent(
        candidate_tool="inspect_logs",
        proposed_input={"target": "host_a"},
        purpose="Consider next step",
        rationale="Unverified consideration",
        evidence_ids=decision.evidence_ids,
    )
    plan = planner.create_plan(
        incident_state=state,
        decision=decision,
        review=review,
        objective="Human-reviewed options",
        candidates=(candidate, candidate.model_copy(update={"candidate_tool": "test_response"})),
    )
    policy = CurrentPolicy()
    promotions = PromotionService(
        store=store, registry=registry, policy=policy, authority=authority
    )
    approvals = ApprovalManager()
    bridge = ExecutionBridge(promotions=promotions, approvals=approvals, authority=authority)
    planning = state, decision, review, store, incidents, registry, planner, candidate, authority
    workflow = planning, plan, policy, promotions, approvals, bridge, authority
    assert llm.call_count == 1
    assert read.call_count == write.call_count == 0
    return workflow, read, write


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "read",
        "write",
        "without_approval",
        "stale",
        "policy",
        "tool",
        "tamper",
        "replay",
        "state_authorization",
    ],
)
async def test_saved_model_pipeline_through_explicit_bridge(environment, scenario):
    workflow, read, write = environment
    planning, _, policy, service, approvals, bridge, authority = workflow
    state, _, _, store, *_ = planning
    before = state.model_dump_json()
    response_review = reviewed(workflow, "inspect_logs" if scenario == "read" else "test_response")
    request = service.request_promotion(response_review)
    assert read.call_count == write.call_count == 0
    assert approvals.list() == ()
    if scenario == "stale":
        store.append_evidence(
            request.target.snapshot,
            Evidence(
                incident_id=state.incident_id,
                source="later",
                summary="More evidence",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
        with pytest.raises(StaleSnapshotError):
            service.promote(request)
    elif scenario in ("policy", "tool"):
        if scenario == "policy":
            policy.override = PolicyDecision.DENY
        else:
            old = planning[5].get("test_response")
            planning[5]._tools["test_response"] = Tool(
                metadata=old.metadata.model_copy(
                    update={"description": "Changed capability description"}
                ),
                input_model=old.input_model,
                output_model=old.output_model,
                handler=old.handler,
            )
        with pytest.raises(PromotionPolicyDenied if scenario == "policy" else ToolMetadataChanged):
            service.promote(request)
    else:
        value = service.promote(request)
        assert read.call_count == write.call_count == 0
        assert approvals.list() == ()
        if scenario == "read":
            assert (await bridge.execute(value)).output.result == "ok"
            assert read.call_count == 1
        else:
            with pytest.raises(ApprovalRequiredError):
                await bridge.execute(value)
            if scenario == "state_authorization":
                state_request = planning[4].propose_change(
                    planning[2],
                    changes=(SeverityChange(before="info", after="high"),),
                    reason="State only",
                )
                state_auth = authorize(planning[4], authority, state_request, planning[2])
                with pytest.raises(ApprovalBindingError):
                    await bridge.execute(value, approval_id=state_auth.authorization_id)
            elif scenario != "without_approval":
                approval = approve(workflow, value)
                if scenario == "tamper":
                    approvals._requests[approval.approval_id] = approval.model_copy(
                        update={"action_input_json": '{"target":"other"}'}
                    )
                    with pytest.raises(ApprovalBindingError):
                        await bridge.execute(value, approval_id=approval.approval_id)
                else:
                    await bridge.execute(value, approval_id=approval.approval_id)
                    assert write.call_count == 1
                    if scenario == "replay":
                        with pytest.raises(ActionAlreadyAttemptedError):
                            await bridge.execute(value, approval_id=approval.approval_id)
                        assert write.call_count == 1
        if scenario in ("read", "write", "replay"):
            success = [e for e in bridge.audit_events() if e.outcome == "succeeded"]
            assert len(success) == 1
            assert success[0].promoted_id == value.promoted_id
            assert success[0].response_review_id == response_review.review_id
    if scenario not in ("read", "write", "replay"):
        assert read.call_count == write.call_count == 0
    assert state.model_dump_json() == before
    if scenario != "stale":
        assert store.load(state.incident_id).state == state
