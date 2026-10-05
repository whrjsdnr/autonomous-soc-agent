import pytest_asyncio

from soc_agent.offline_evaluation import (
    OfflineEvaluationPlanner,
    OfflineEvaluationStore,
    migrate_offline_evaluation,
)
from tests.integration.improvement_candidates.conftest import (
    candidate_case,
    dataset_case,
    feedback_case,
    runtime_case,
)

__all__ = ["candidate_case", "dataset_case", "feedback_case", "runtime_case"]


@pytest_asyncio.fixture
async def planning_case(candidate_case):
    c = candidate_case
    c.proposals = c.improvement.propose(c.dataset.dataset_id)
    c.candidate = c.proposals.candidates[0]
    migrate_offline_evaluation(c.store.database)
    c.offline = OfflineEvaluationStore(c.candidates)
    c.offline_planner = OfflineEvaluationPlanner(c.offline)
    return c
