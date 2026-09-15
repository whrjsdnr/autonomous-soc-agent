from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from pydantic import BaseModel, ConfigDict, JsonValue

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessment
from soc_agent.execution import GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.response import ResponsePlan, ResponseStep, ResponseStepStatus
from soc_agent.state import Evidence, IncidentState, Severity
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel
from soc_agent.verification import (
    VerificationOrchestrator,
    VerificationPlan,
    VerificationPlanDraft,
    VerificationResult,
)
from soc_agent.verification.validator import normalize_plan


class Query(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    window_seconds: int = 300


class Record(BaseModel):
    message: str


@dataclass(frozen=True)
class Context:
    state: IncidentState
    assessment: ThreatAssessment
    response: ResponsePlan


@dataclass(frozen=True)
class Runtime:
    mock: MockTool[Query, Record]
    registry: ToolRegistry
    executor: GovernedExecutor
    orchestrator: VerificationOrchestrator


def make_tool(
    *,
    name: str = "search_auth_logs_after_action",
    permission: ToolPermission = ToolPermission.NETWORK_READ,
    risk: ToolRiskLevel = ToolRiskLevel.READ_ONLY,
    responses: Sequence[JsonValue | Exception] | None = None,
) -> MockTool[Query, Record]:
    return MockTool(
        metadata=ToolMetadata(
            name=name, description="Fixture", permission=permission, risk_level=risk
        ),
        input_model=Query,
        output_model=Record,
        responses=[{"message": "No attempts after block"}] if responses is None else responses,
    )


@pytest.fixture
def context() -> Context:
    state = IncidentState()
    record = Evidence(
        incident_id=state.incident_id,
        source="auth.log",
        summary="100 attempts before action",
        raw_data="PRE_ACTION_RAW_SECRET",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    state = state.add_evidence(record)
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity=Severity.HIGH,
        confidence=0.84,
        summary="Likely password spraying",
        supporting_evidence_ids=(record.evidence_id,),
    )
    step = ResponseStep(
        tool_name="block_ip",
        tool_input={"ip": "203.0.113.20"},
        purpose="Stop authentication attempts from this IP",
    )
    response = ResponsePlan(
        incident_id=state.incident_id,
        assessment_id=assessment.assessment_id,
        goal="Scoped containment",
        steps=(step,),
    )
    response = response.transition_step(step.step_id, ResponseStepStatus.EXECUTING)
    response = response.transition_step(step.step_id, ResponseStepStatus.COMPLETED)
    return Context(state, assessment, response)


@pytest.fixture
def runtime() -> Runtime:
    mock = make_tool()
    registry = ToolRegistry()
    registry.register(mock.tool)
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    return Runtime(mock, registry, executor, VerificationOrchestrator(executor=executor))


@pytest.fixture
def draft_payload() -> dict[str, JsonValue]:
    return {
        "goal": "Check the intended scoped block effect",
        "steps": [
            {
                "tool_name": "search_auth_logs_after_action",
                "tool_input": {"ip": "203.0.113.20"},
                "purpose": "Check post-action attempts",
                "expected_signal": "No attempts after block",
            }
        ],
    }


@pytest.fixture
def plan(
    context: Context, runtime: Runtime, draft_payload: dict[str, JsonValue]
) -> VerificationPlan:
    return normalize_plan(
        VerificationPlanDraft.model_validate(draft_payload),
        state=context.state,
        assessment=context.assessment,
        response=context.response,
        response_step_id=context.response.steps[0].step_id,
        tools={runtime.mock.tool.metadata.name: runtime.mock.tool},
    )


# Collection fixture deliberately uses the actual governed path.


@pytest_asyncio.fixture
async def collected(
    context: Context, runtime: Runtime, plan: VerificationPlan
) -> VerificationResult:
    return await runtime.orchestrator.execute_plan(
        incident_state=context.state,
        response_plan=context.response,
        plan=plan,
    )
