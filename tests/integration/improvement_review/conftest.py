from types import SimpleNamespace

import pytest
from tests.integration.offline_comparison.conftest import (
    candidate_case,
    coverage_case,
    dataset_case,
    feedback_case,
    planning_case,
    runtime_case,
)
from tests.unit.identity.conftest import Boundary

from soc_agent.improvement_review import (
    ImprovementReviewService,
    ImprovementReviewStore,
    migrate_improvement_review,
)
from soc_agent.review.authorization import RBACPermissionVerifier

__all__ = [
    "candidate_case",
    "coverage_case",
    "dataset_case",
    "feedback_case",
    "planning_case",
    "runtime_case",
]


@pytest.fixture
def review_case(coverage_case):
    c = coverage_case
    artifacts = c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id)
    migrate_improvement_review(c.store.database)
    store = ImprovementReviewStore(c.comparison_store)
    request = store.create_request(artifacts.comparison.comparison_id)
    boundary = Boundary()
    service = ImprovementReviewService(
        store,
        provider=boundary.provider,
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=boundary.roles),
    )
    return SimpleNamespace(
        source=c,
        artifacts=artifacts,
        store=store,
        request=request,
        boundary=boundary,
        service=service,
    )
