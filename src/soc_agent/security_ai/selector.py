"""One LLM selection pass; inference belongs to a future coordinator."""

from types import MappingProxyType

from soc_agent.llm import LLMClient
from soc_agent.security_ai.registry import SecurityAIRegistry
from soc_agent.security_ai.selection_errors import NoSecurityAIAvailableError
from soc_agent.security_ai.selection_models import SecurityAISelectionDraft, SecurityAISelectionPlan
from soc_agent.security_ai.selection_prompts import build_selection_request
from soc_agent.security_ai.selection_validator import normalize_selection
from soc_agent.security_ai.signals import AISignal
from soc_agent.state import IncidentState


class SecurityAISelector:
    def __init__(self, *, llm_client: LLMClient, registry: SecurityAIRegistry) -> None:
        self._llm = llm_client
        self._registry = registry

    async def select(
        self, *, incident: IncidentState, signals: tuple[AISignal, ...] = ()
    ) -> SecurityAISelectionPlan:
        state = IncidentState.model_validate(incident.model_dump(warnings=False))
        models = MappingProxyType(
            {metadata.name: self._registry.get(metadata.name) for metadata in self._registry.list()}
        )
        if not models:
            raise NoSecurityAIAvailableError("Cannot select without registered security AI models")
        request = build_selection_request(state, signals, models)
        draft = await self._llm.generate_structured(
            request=request, response_model=SecurityAISelectionDraft
        )
        return normalize_selection(draft, incident_id=state.incident_id, models=models)
