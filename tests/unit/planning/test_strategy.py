import pytest
from pydantic import ValidationError
from tests.unit.offline_comparison.test_coverage import inputs
from tests.unit.offline_evaluation.test_planning import candidate_for

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ApprovalRequiredError
from soc_agent.improvement_candidates.models import CandidateType
from soc_agent.improvement_candidates.strategy import (
    UnsupportedStrategyProposal,
    compile_candidate_strategy,
)
from soc_agent.llm import MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.errors import InvalidPlannedToolInputError, UnknownPlannedToolError
from soc_agent.planning.strategy import (
    ExplicitStrategyProvider,
    InvestigationStrategy,
    StrategyCoverageError,
    UnsatisfiableStrategy,
)
from soc_agent.policy import PolicyEngine
from soc_agent.review.identity import content_digest
from soc_agent.state import IncidentState
from soc_agent.tools import Tool, ToolRiskLevel
from soc_agent.tools import ToolPermission as P


def test_canonical_immutable_contract_and_explicit_compiler():
    strategy = InvestigationStrategy(required_permissions=(P.SYSTEM_READ, P.FILE_READ, P.FILE_READ))
    assert strategy.required_permissions == (P.FILE_READ, P.SYSTEM_READ)
    assert content_digest(strategy) == content_digest(
        InvestigationStrategy(required_permissions=(P.FILE_READ, P.SYSTEM_READ))
    )
    with pytest.raises(ValidationError):
        strategy.operation = "EXECUTE"
    source, *_ = inputs()
    compiled = compile_candidate_strategy(source)
    assert compiled == InvestigationStrategy(required_permissions=(P.NETWORK_READ,))
    assert compile_candidate_strategy(source) == compiled


@pytest.mark.parametrize(
    "values",
    [
        {"required_permissions": ()},
        {"required_permissions": (P.NETWORK_WRITE,)},
        {"required_permissions": (P.SYSTEM_WRITE,)},
        {"required_permissions": (P.FILE_WRITE,)},
        {"required_permissions": ("invented",)},
        {"required_permissions": (P.FILE_READ,), "operation": "EXECUTE_CODE"},
        {"required_permissions": (P.FILE_READ,), "executable": "arbitrary text"},
    ],
)
def test_reject_non_read_only_or_free_form_contract(values):
    with pytest.raises(ValidationError):
        InvestigationStrategy.model_validate(values)


@pytest.mark.parametrize("kind", list(CandidateType))
def test_review_proposals_are_never_compiled(kind):
    candidate, _ = candidate_for(kind)
    with pytest.raises(UnsupportedStrategyProposal):
        compile_candidate_strategy(candidate)


def add_tool(registry, mock_tool, name, permission):
    registry.register(
        Tool(
            mock_tool.tool.metadata.model_copy(update={"name": name, "permission": permission}),
            mock_tool.tool.input_model,
            mock_tool.tool.output_model,
            mock_tool.tool.handler,
        )
    )


@pytest.mark.asyncio
async def test_explicit_multiple_permissions_use_registry_without_execution(
    registry, mock_tool, response
):
    add_tool(registry, mock_tool, "opaque_inspector", P.NETWORK_READ)
    payload = response | {
        "steps": [
            *response["steps"],
            response["steps"][0] | {"tool_name": "opaque_inspector"},
        ]
    }
    strategy = InvestigationStrategy(required_permissions=(P.NETWORK_READ, P.FILE_READ))
    llm = MockLLMClient([payload])
    state = IncidentState()
    before = state.model_dump()
    plan = await InvestigationPlanner(
        llm_client=llm,
        registry=registry,
        strategy_provider=ExplicitStrategyProvider(strategy),
    ).create_plan(state)
    assert tuple(s.tool_name for s in plan.steps) == ("search_auth_logs", "opaque_inspector")
    assert llm.call_count == 1 and mock_tool.call_count == 0
    assert state.model_dump() == before


@pytest.mark.asyncio
async def test_missing_coverage_uses_metadata_and_never_repairs(registry, mock_tool, response):
    add_tool(registry, mock_tool, "network_read_named_but_file_permission", P.FILE_READ)
    add_tool(registry, mock_tool, "opaque_network_capability", P.NETWORK_READ)
    payload = response | {
        "steps": [response["steps"][0] | {"tool_name": "network_read_named_but_file_permission"}]
    }
    llm = MockLLMClient([payload, response])
    with pytest.raises(StrategyCoverageError):
        await InvestigationPlanner(
            llm_client=llm,
            registry=registry,
            strategy_provider=ExplicitStrategyProvider(
                InvestigationStrategy(required_permissions=(P.NETWORK_READ,))
            ),
        ).create_plan(IncidentState())
    assert llm.call_count == 1 and mock_tool.call_count == 0


@pytest.mark.asyncio
async def test_unsatisfiable_strategy_never_calls_llm_or_fabricates_tool(registry, response):
    llm = MockLLMClient([response])
    catalog = registry.list()
    with pytest.raises(UnsatisfiableStrategy):
        await InvestigationPlanner(
            llm_client=llm,
            registry=registry,
            strategy_provider=ExplicitStrategyProvider(
                InvestigationStrategy(required_permissions=(P.SYSTEM_READ,))
            ),
        ).create_plan(IncidentState())
    assert registry.list() == catalog and llm.call_count == 0


@pytest.mark.parametrize("invalid", ["unregistered", "bad_input"])
@pytest.mark.asyncio
async def test_strategy_does_not_replace_existing_validation(registry, response, invalid):
    step = response["steps"][0] | (
        {"tool_name": "invented_tool"} if invalid == "unregistered" else {"tool_input": {}}
    )
    llm = MockLLMClient([response | {"steps": [step]}])
    with pytest.raises(
        UnknownPlannedToolError if invalid == "unregistered" else InvalidPlannedToolInputError
    ):
        await InvestigationPlanner(
            llm_client=llm,
            registry=registry,
            strategy_provider=ExplicitStrategyProvider(
                InvestigationStrategy(required_permissions=(P.FILE_READ,))
            ),
        ).create_plan(IncidentState())
    assert llm.call_count == 1


@pytest.mark.asyncio
async def test_none_provider_preserves_planner_context_and_behavior(registry, response):
    state = IncidentState()
    clients = [MockLLMClient([response]), MockLLMClient([response])]
    plans = []
    for client, provider in zip(clients, (None, ExplicitStrategyProvider()), strict=True):
        plans.append(
            await InvestigationPlanner(
                llm_client=client, registry=registry, strategy_provider=provider
            ).create_plan(state)
        )
    assert clients[0].requests == clients[1].requests
    assert [(s.tool_name, s.tool_input) for s in plans[0].steps] == [
        (s.tool_name, s.tool_input) for s in plans[1].steps
    ]


@pytest.mark.asyncio
async def test_coverage_cannot_authorize_an_existing_write_step(registry, mock_tool, response):
    registry.register(
        Tool(
            mock_tool.tool.metadata.model_copy(
                update={
                    "name": "local_write_probe",
                    "permission": P.NETWORK_WRITE,
                    "risk_level": ToolRiskLevel.LOW,
                }
            ),
            mock_tool.tool.input_model,
            mock_tool.tool.output_model,
            mock_tool.tool.handler,
        )
    )
    llm = MockLLMClient(
        [
            response
            | {
                "steps": [
                    *response["steps"],
                    response["steps"][0] | {"tool_name": "local_write_probe"},
                ]
            }
        ]
    )
    state = IncidentState()
    plan = await InvestigationPlanner(
        llm_client=llm,
        registry=registry,
        strategy_provider=ExplicitStrategyProvider(
            InvestigationStrategy(required_permissions=(P.FILE_READ,))
        ),
    ).create_plan(state)
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    step = plan.steps[-1]
    with pytest.raises(ApprovalRequiredError):
        executor.preflight(
            ActionProposal(
                incident_id=state.incident_id, tool_name=step.tool_name, tool_input=step.tool_input
            )
        )
    assert mock_tool.call_count == 0 and state.evidence == ()
