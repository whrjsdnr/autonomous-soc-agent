from uuid import uuid4

import pytest_asyncio

from soc_agent.feedback import DiagnosticLabel, Verdict
from soc_agent.improvement_candidates import (
    ImprovementCandidateService,
    ImprovementCandidateStore,
    migrate_candidates,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewOutcome
from tests.integration.experience.test_capture import capture_service
from tests.integration.improvement_dataset.conftest import (
    dataset_case,
    feedback_case,
    runtime_case,
    submit,
)
from tests.unit.investigation_runtime.conftest import review_for

__all__ = ["dataset_case", "feedback_case", "runtime_case"]


@pytest_asyncio.fixture
async def candidate_case(dataset_case):
    c = dataset_case
    first_feedback = submit(c, Verdict.INCORRECT, (DiagnosticLabel.FALSE_POSITIVE,))
    first_evaluation = c.evaluation
    await c.runtime.advance(c.incident_id, review=review_for(c, ReviewOutcome.REJECTED))
    await c.runtime.advance(c.incident_id)
    c.experience = capture_service(c).capture(c.incident_id)
    c.evaluation = c.evaluator.evaluate(c.experience.experience_id)
    c.request = c.request.model_copy(
        update={
            "submission_id": uuid4(),
            "experience_id": c.experience.experience_id,
            "experience_digest": content_digest(c.experience),
            "evaluation_id": c.evaluation.evaluation_id,
            "evaluation_digest": content_digest(c.evaluation),
        }
    )
    second_feedback = submit(c, Verdict.INCORRECT, (DiagnosticLabel.FALSE_POSITIVE,))
    c.dataset = c.builder.build((c.evaluation.evaluation_id, first_evaluation.evaluation_id))
    c.feedback_refs = (first_feedback, second_feedback)
    migrate_candidates(c.store.database)
    c.candidates = ImprovementCandidateStore(c.datasets)
    c.improvement = ImprovementCandidateService(c.candidates)
    return c
