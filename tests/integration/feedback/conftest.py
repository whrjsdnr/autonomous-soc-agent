from uuid import uuid4

import pytest_asyncio

from soc_agent.feedback import (
    AnalystFeedbackService,
    FeedbackRequest,
    FeedbackStore,
    Verdict,
    feedback_context,
    migrate_feedback,
)
from soc_agent.review.authorization import HumanRole, RBACPermissionVerifier
from soc_agent.review.identity import content_digest
from tests.integration.evaluation.test_evaluation import evaluator
from tests.integration.experience.test_capture import capture_service
from tests.unit.identity.conftest import Boundary
from tests.unit.investigation_runtime.conftest import decision_ready, runtime_case

__all__ = ["runtime_case"]


@pytest_asyncio.fixture
async def feedback_case(runtime_case):
    c = runtime_case(durable_workflow=True)
    await decision_ready(c)
    c.experience = capture_service(c).capture(c.incident_id)
    c.evaluator = evaluator(c)
    c.evaluation = c.evaluator.evaluate(c.experience.experience_id)
    migrate_feedback(c.store.database)
    c.feedback_store = FeedbackStore(c.evaluator.store)
    c.boundary = Boundary()
    c.feedback = AnalystFeedbackService(
        c.feedback_store,
        provider=c.boundary.provider,
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=c.boundary.roles),
    )
    c.request = FeedbackRequest(
        submission_id=uuid4(),
        incident_id=c.incident_id,
        experience_id=c.experience.experience_id,
        experience_digest=content_digest(c.experience),
        evaluation_id=c.evaluation.evaluation_id,
        evaluation_digest=content_digest(c.evaluation),
        verdict=Verdict.CORRECT,
    )
    return c


def issue(c, request=None, roles=(HumanRole.ANALYST,), subject="alice"):
    return c.boundary.issue(feedback_context(request or c.request, c.experience), roles, subject)
