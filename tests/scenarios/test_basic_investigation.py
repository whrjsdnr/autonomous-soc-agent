"""Suspicious authentication for alice: collect records without classification."""

import json

import pytest
from pydantic import BaseModel

from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import (
    InvestigationOrchestrator,
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStatus,
)
from soc_agent.policy import PolicyEngine
from soc_agent.state import IncidentState
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class UserQuery(BaseModel):
    user: str


class SecurityRecords(BaseModel):
    records: list[str]


@pytest.mark.asyncio
async def test_basic_authentication_investigation() -> None:
    state = IncidentState()
    registry = ToolRegistry()
    samples = {
        "login_failures": ["alice: 327 failed logins"],
        "source_activity": ["203.0.113.10: 327 authentication requests"],
        "host_sessions": ["alice: one active session on server-01"],
    }
    mocks = []
    for name, records in samples.items():
        mock = MockTool(
            metadata=ToolMetadata(
                name=name,
                description="Read-only fixture data",
                permission=ToolPermission.SYSTEM_READ,
                risk_level=ToolRiskLevel.READ_ONLY,
            ),
            input_model=UserQuery,
            output_model=SecurityRecords,
            responses=[{"records": records}],
        )
        registry.register(mock.tool)
        mocks.append(mock)
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    orchestrator = InvestigationOrchestrator(executor=executor)
    plan = InvestigationPlan(
        incident_id=state.incident_id,
        steps=tuple(
            InvestigationStep(
                tool_name=name, tool_input={"user": "alice"}, purpose=f"Collect {name} records"
            )
            for name in samples
        ),
    )
    result = await orchestrator.execute_plan(incident_state=state, plan=plan)
    assert [mock.call_count for mock in mocks] == [1, 1, 1]
    assert len(result.incident_state.evidence) == 3
    for step, evidence in zip(result.plan.steps, result.incident_state.evidence, strict=True):
        assert step.status is InvestigationStepStatus.COMPLETED
        assert step.evidence_id == evidence.evidence_id
        assert evidence.incident_id == state.incident_id
        assert evidence.tool_name == step.tool_name
        assert json.loads(evidence.raw_data)["output"]["records"] == samples[step.tool_name]
    assert state.evidence == ()
    assert result.incident_state.severity == state.severity
    assert result.incident_state.confidence == state.confidence
    assert result.incident_state.observations == result.incident_state.hypotheses == ()
