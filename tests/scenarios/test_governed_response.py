"""AI recommends; policy gates; a human approves one exact mock containment action."""

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.response import ResponseCoordinator, ResponsePlanner, ResponseStepStatus
from soc_agent.state import Evidence, IncidentState, Severity
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class Target(BaseModel):
    ip: str


class Result(BaseModel):
    accepted: bool


@pytest.mark.asyncio
@pytest.mark.parametrize("risk", [ToolRiskLevel.HIGH, ToolRiskLevel.DESTRUCTIVE])
async def test_password_spraying_governed_response(risk: ToolRiskLevel) -> None:
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="tool:auth_logs",
        summary="One IP attempted authentication across seven accounts",
        raw_data="Fixture logs",
        observed_at=datetime.now(UTC),
    )
    state = state.add_evidence(evidence)
    evidence_ids = [str(evidence.evidence_id)]
    analysis_llm = MockLLMClient(
        [
            {
                "observations": [
                    {
                        "ref": "O1",
                        "statement": evidence.summary,
                        "supporting_evidence_ids": evidence_ids,
                    }
                ],
                "hypotheses": [
                    {
                        "ref": "H1",
                        "statement": "Possible password spraying",
                        "confidence": 0.86,
                        "supporting_evidence_ids": evidence_ids,
                    }
                ],
                "assessment": {
                    "severity": "high",
                    "confidence": 0.84,
                    "summary": "Likely password spraying",
                    "supporting_evidence_ids": evidence_ids,
                    "supporting_observation_refs": ["O1"],
                    "supporting_hypothesis_refs": ["H1"],
                },
            }
        ]
    )
    analysis = await ThreatAssessor(llm_client=analysis_llm).assess(state)
    state, assessment = analysis.incident_state, analysis.threat_assessment
    assert assessment.severity is Severity.HIGH
    assert analysis_llm.call_count == 1
    assessment_before = assessment.model_dump_json()
    registry = ToolRegistry()
    # Read monitoring information; do not mislabel configuration changes as read-only.
    mocks = []
    for name, permission, level in (
        ("review_auth_monitoring", ToolPermission.NETWORK_READ, ToolRiskLevel.LOW),
        (
            "block_ip" if risk == ToolRiskLevel.HIGH else "wipe_host",
            ToolPermission.NETWORK_WRITE,
            risk,
        ),
        ("review_followup", ToolPermission.NETWORK_READ, ToolRiskLevel.LOW),
    ):
        mock = MockTool(
            metadata=ToolMetadata(
                name=name,
                description="Scenario fixture only",
                permission=permission,
                risk_level=level,
            ),
            input_model=Target,
            output_model=Result,
            responses=[{"accepted": True}],
        )
        registry.register(mock.tool)
        mocks.append(mock)
    llm = MockLLMClient(
        [
            {
                "goal": "Scoped response to suspicious authentication",
                "steps": [
                    {
                        "tool_name": m.tool.metadata.name,
                        "tool_input": {"ip": "203.0.113.20"},
                        "purpose": "Address assessed authentication risk",
                    }
                    for m in mocks
                ],
            }
        ]
    )
    plan = await ResponsePlanner(llm_client=llm, registry=registry).create_plan(
        incident_state=state, threat_assessment=assessment
    )
    assert llm.call_count == 1 and all(m.call_count == 0 for m in mocks)
    approvals = ApprovalManager()
    executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    coordinator = ResponseCoordinator(executor=executor)
    result = await coordinator.execute_plan(incident_state=state, plan=plan)
    assert [s.status for s in result.plan.steps] == [
        ResponseStepStatus.COMPLETED,
        ResponseStepStatus.BLOCKED,
        ResponseStepStatus.PENDING,
    ]
    assert [m.call_count for m in mocks] == [1, 0, 0]
    blocked_plan = result.plan
    action = coordinator.prepare_step(
        incident_state=state, plan=blocked_plan, step_id=plan.steps[1].step_id
    )
    if risk == ToolRiskLevel.HIGH:
        request = executor.request_approval(action, reason="Human reviews this exact containment")
    else:
        request = approvals.create(
            incident_id=state.incident_id,
            metadata=mocks[1].tool.metadata,
            reason="Cannot override policy",
            action_id=action.action_id,
            action_input_json=action.tool_input,
        )
    approvals.approve(request.approval_id, actor="human-operator")
    result = await coordinator.execute_step(
        incident_state=state,
        plan=blocked_plan,
        step_id=plan.steps[1].step_id,
        approval_id=request.approval_id,
    )
    if risk == ToolRiskLevel.HIGH:
        assert result.plan.steps[1].status is ResponseStepStatus.COMPLETED
        assert [m.call_count for m in mocks] == [1, 1, 0]
    else:
        assert result.plan.steps[1].status is ResponseStepStatus.BLOCKED
        assert result.plan.steps[1].failure.error_type == "ExecutionDeniedError"
        assert [m.call_count for m in mocks] == [1, 0, 0]
    assert result.incident_state == state
    assert assessment.model_dump_json() == assessment_before
    assert result.plan.assessment_id == assessment.assessment_id
    assert result.plan.steps[1].action_id == action.action_id
