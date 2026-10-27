"""One structured LLM request, followed by deterministic plan validation."""

from pydantic import Field, create_model

from soc_agent.investigation import InvestigationPlan
from soc_agent.llm import LLMClient
from soc_agent.planning.errors import PlanningError
from soc_agent.planning.models import LLMInvestigationPlanDraft, LLMInvestigationStepDraft
from soc_agent.planning.prompts import build_planner_input, build_request
from soc_agent.planning.strategy import (
    InvestigationStrategy,
    InvestigationStrategyProvider,
    ensure_satisfiable,
    validate_strategy,
)
from soc_agent.planning.validator import normalize_plan
from soc_agent.state import IncidentState
from soc_agent.tools import ToolRegistry


class InvestigationPlanner:
    """Produces plans only; caller separately invokes the governed orchestrator.

    Registry/schema definitions are trusted setup. No hidden retries or deduplication.
    LLM errors propagate with their original boundary meaning.
    """

    def __init__(
        self,
        *,
        llm_client: LLMClient,
        registry: ToolRegistry,
        strategy_provider: InvestigationStrategyProvider | None = None,
        max_steps: int = 8,
        draft_model: type[LLMInvestigationPlanDraft] = LLMInvestigationPlanDraft,
    ) -> None:
        if type(max_steps) is not int or not 1 <= max_steps <= 8:
            raise ValueError("Planner step limit must be in [1, 8]")
        self._llm = llm_client
        self._registry = registry
        self._strategy_provider = strategy_provider
        self._max_steps = max_steps
        if not issubclass(draft_model, LLMInvestigationPlanDraft):
            raise ValueError("Planner draft must retain the existing plan contract")
        self.last_draft: LLMInvestigationPlanDraft | None = None
        self._response_model = (
            draft_model
            if max_steps == 8
            else create_model(
                "LLMInvestigationPlanDraft",
                __base__=draft_model,
                steps=(
                    tuple[LLMInvestigationStepDraft, ...],
                    Field(min_length=1, max_length=max_steps),
                ),
            )
        )

    async def create_plan(self, incident_state: IncidentState) -> InvestigationPlan:
        self.last_draft = None
        tools = {
            metadata.name: self._registry.get(metadata.name)
            for metadata in self._registry.list()
            if self._registry.execution_guard is None
            or self._registry.execution_guard.planning_allowed(incident_state.incident_id, metadata)
        }
        if not tools:
            raise PlanningError("Cannot plan without registered tools")
        strategy = (
            self._strategy_provider.get_strategy(incident_state)
            if self._strategy_provider is not None
            else None
        )
        if strategy is not None:
            strategy = InvestigationStrategy.model_validate(strategy.model_dump())
            ensure_satisfiable(strategy, tools)
        context = build_planner_input(incident_state, tools)
        draft = await self._llm.generate_structured(
            request=build_request(context, max_steps=self._max_steps),
            response_model=self._response_model,
        )
        # Revalidate independently of a custom client implementation.
        draft = self._response_model.model_validate(draft.model_dump())
        # Extended advisory fields never enter the executable plan contract.
        executable = LLMInvestigationPlanDraft(goal=draft.goal, steps=draft.steps)
        plan = normalize_plan(executable, incident_id=context.incident_id, tools=tools)
        result = validate_strategy(plan, strategy, tools=tools) if strategy is not None else plan
        self.last_draft = draft
        return result
