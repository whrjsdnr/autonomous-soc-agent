from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessment
from soc_agent.execution import GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.response import ResponseCoordinator
from soc_agent.state import Evidence, Hypothesis, IncidentState, Observation, Severity
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str


class Output(BaseModel):
    success: bool


@pytest.fixture
def context():
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="tool:auth_logs",
        summary="43 failed logins",
        raw_data="SECRET RAW LOG",
        observed_at=datetime.now(UTC),
        tool_name="auth_logs",
    )
    state = state.add_evidence(evidence)
    observation = Observation(
        statement="Repeated authentication failures",
        supporting_evidence_ids=(evidence.evidence_id,),
    )
    hypothesis = Hypothesis(
        statement="Possible password spraying",
        confidence=0.86,
        supporting_evidence_ids=(evidence.evidence_id,),
    )
    state = state.add_observation(observation).add_hypothesis(hypothesis)
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity=Severity.HIGH,
        confidence=0.84,
        summary="Likely password spraying",
        supporting_evidence_ids=(evidence.evidence_id,),
        supporting_observation_ids=(observation.observation_id,),
        supporting_hypothesis_ids=(hypothesis.hypothesis_id,),
    )
    return state, assessment


@pytest.fixture
def setup_tools():
    def build(risk=ToolRiskLevel.HIGH, responses=None):
        mock = MockTool(
            metadata=ToolMetadata(
                name="block_ip",
                description="Fixture action",
                risk_level=risk,
                permission=ToolPermission.NETWORK_READ
                if risk in (ToolRiskLevel.LOW, ToolRiskLevel.READ_ONLY)
                else ToolPermission.NETWORK_WRITE,
            ),
            input_model=Input,
            output_model=Output,
            responses=[{"success": True}] if responses is None else responses,
        )
        registry = ToolRegistry()
        registry.register(mock.tool)
        approvals = ApprovalManager()
        executor = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
        return mock, registry, approvals, executor, ResponseCoordinator(executor=executor)

    return build


@pytest.fixture
def payload():
    return {
        "goal": "Scoped containment",
        "steps": [
            {
                "tool_name": "block_ip",
                "tool_input": {"ip": "203.0.113.20"},
                "purpose": "Temporarily contain source",
            }
        ],
    }
