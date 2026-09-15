"""Real boundary composition with deterministic LLM, Tool, and AI adapters."""

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, JsonValue

from soc_agent.adaptive import (
    AdaptiveInvestigationPlanner,
    BoundedInvestigationCoordinator,
    InvestigationContext,
)
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIInvestigator,
    SecurityAIModelMetadata,
    SecurityAIRegistry,
)
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import MockTool, ToolMetadata, ToolRegistry


class Features(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failed_login_count: int
    unique_accounts: int = 7


class Query(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator: str


class Reputation(BaseModel):
    reputation: str


def ai_choice(name: str = "auth_anomaly", count: int = 43) -> dict[str, JsonValue]:
    return {
        "decision": "continue_with_ai",
        "reason": "Evaluate authentication uncertainty",
        "tool": None,
        "ai": {
            "model_name": name,
            "model_input": {"failed_login_count": count},
            "purpose": "Inspect authentication activity",
        },
    }


def tool_choice(name: str = "ioc_lookup", indicator: str = "203.0.113.7") -> dict[str, JsonValue]:
    return {
        "decision": "continue_with_tool",
        "reason": "Source reputation is missing",
        "ai": None,
        "tool": {
            "tool_name": name,
            "tool_input": {"indicator": indicator},
            "purpose": "Inspect source reputation",
        },
    }


def terminal(choice: str = "ready_for_assessment") -> dict[str, JsonValue]:
    return {
        "decision": choice,
        "reason": "Enough investigation for the next stage",
        "tool": None,
        "ai": None,
    }


def initial_context() -> InvestigationContext:
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="auth.log",
            summary="43 failed logins targeting 7 accounts from 203.0.113.7",
            raw_data="SECRET_ORIGINAL_LOGS",
            observed_at=utc_now(),
        )
    )
    return InvestigationContext(incident=state)


@dataclass
class Runtime:
    coordinator: BoundedInvestigationCoordinator
    planner: AdaptiveInvestigationPlanner
    client: MockLLMClient
    tools: ToolRegistry
    models: SecurityAIRegistry
    tool: MockTool[Query, Reputation]
    auth: MockSecurityAI[Features]
    network: MockSecurityAI[Features]
    approvals: ApprovalManager
    orchestrator: InvestigationOrchestrator
    investigator: SecurityAIInvestigator


def runtime(
    responses: list[JsonValue],
    *,
    tool_responses: list[JsonValue | Exception] | None = None,
    auth_responses: list[JsonValue | Exception] | None = None,
    network_responses: list[JsonValue | Exception] | None = None,
    policy: PolicyEngine | None = None,
) -> Runtime:
    tools, models, approvals = ToolRegistry(), SecurityAIRegistry(), ApprovalManager()
    tool = MockTool(
        metadata=ToolMetadata(
            name="ioc_lookup",
            description="Read reputation",
            permission="network_read",
            risk_level="read_only",
        ),
        input_model=Query,
        output_model=Reputation,
        responses=tool_responses if tool_responses is not None else [{"reputation": "malicious"}],
    )
    tools.register(tool.tool)
    auth = MockSecurityAI(
        metadata=SecurityAIModelMetadata(
            name="auth_anomaly",
            version="1.0",
            description="Analyze authentication features",
            task_type="anomaly_detection",
            input_type="authentication_event",
        ),
        input_model=Features,
        responses=auth_responses
        if auth_responses is not None
        else [{"prediction": "anomalous", "scores": {"anomaly_score": 0.91}}],
    )
    network = MockSecurityAI(
        metadata=SecurityAIModelMetadata(
            name="network_anomaly",
            version="1.0",
            description="Analyze network features",
            task_type="anomaly_detection",
            input_type="generic_feature_vector",
        ),
        input_model=Features,
        responses=network_responses
        if network_responses is not None
        else [{"prediction": "anomalous"}],
    )
    models.register(auth.model)
    models.register(network.model)
    client = MockLLMClient(responses)
    planner = AdaptiveInvestigationPlanner(
        llm_client=client, tool_registry=tools, ai_registry=models
    )
    orchestrator = InvestigationOrchestrator(
        executor=GovernedExecutor(
            registry=tools, policy=policy or PolicyEngine(), approvals=approvals
        )
    )
    investigator = SecurityAIInvestigator(registry=models)
    coordinator = BoundedInvestigationCoordinator(
        planner=planner, tool_orchestrator=orchestrator, ai_investigator=investigator
    )
    return Runtime(
        coordinator,
        planner,
        client,
        tools,
        models,
        tool,
        auth,
        network,
        approvals,
        orchestrator,
        investigator,
    )
