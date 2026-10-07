"""Opt-in runtime composition; no active version is selected automatically."""

from soc_agent.improvement_promotion.store import ImprovementPromotionStore
from soc_agent.planning.strategy import InvestigationStrategy
from soc_agent.state import IncidentState


class RegistryBackedInvestigationStrategyProvider:
    def __init__(self, store: ImprovementPromotionStore) -> None:
        self.store = store

    def get_strategy(self, context: IncidentState) -> InvestigationStrategy | None:
        artifact = self.store.get_active_artifact()
        # NONE is the existing implicit no-constraint baseline, not a fabricated version.
        return (
            None
            if artifact is None
            else InvestigationStrategy.model_validate(artifact.content.payload.model_dump())
        )
