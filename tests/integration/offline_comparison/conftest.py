from tests.integration.offline_evaluation.conftest import (
    candidate_case,
    dataset_case,
    feedback_case,
    planning_case,
    runtime_case,
)

__all__ = ["candidate_case", "dataset_case", "feedback_case", "planning_case", "runtime_case"]


from uuid import uuid4

import pytest_asyncio

from soc_agent.feedback import (
    AnalystFeedbackService,
    FeedbackRequest,
    FeedbackStore,
    Verdict,
    migrate_feedback,
)
from soc_agent.feedback.models import CoverageExpectation
from soc_agent.improvement_candidates import (
    CandidateType,
    ImprovementCandidateService,
    ImprovementCandidateStore,
    migrate_candidates,
)
from soc_agent.improvement_dataset import (
    ImprovementDatasetBuilder,
    ImprovementDatasetStore,
    migrate_datasets,
)
from soc_agent.offline_comparison import (
    CoverageConfiguration,
    OfflineComparisonStore,
    OfflineEvaluationRunner,
    migrate_frozen_baselines,
    migrate_offline_comparison,
)
from soc_agent.offline_evaluation import (
    OfflineEvaluationPlanner,
    OfflineEvaluationStore,
    SplitConfig,
    migrate_offline_evaluation,
)
from soc_agent.offline_evaluation.split import partition
from soc_agent.review.authorization import RBACPermissionVerifier
from soc_agent.review.identity import content_digest
from soc_agent.review.models import ReviewOutcome
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.tools.enums import ToolPermission
from tests.integration.evaluation.test_evaluation import evaluator
from tests.integration.experience.test_capture import capture_service
from tests.integration.feedback.conftest import issue
from tests.integration.improvement_dataset.conftest import submit
from tests.unit.identity.conftest import Boundary
from tests.unit.investigation_runtime.conftest import decision_ready, review_for


@pytest_asyncio.fixture
async def coverage_case(feedback_case, runtime_case, monkeypatch):
    from soc_agent.feedback import DiagnosticLabel

    c = feedback_case
    first = c.evaluation
    submit(c, Verdict.INCORRECT, (DiagnosticLabel.MISSED_INVESTIGATION,))
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
    submit(c, Verdict.INCORRECT, (DiagnosticLabel.MISSED_INVESTIGATION,))
    evaluation_ids = [first.evaluation_id, c.evaluation.evaluation_id]
    c.holdout_feedback = []
    c.children = []
    for _ in range(3):
        # All histories must originate in this same repository: StateAnchor binds
        # repository_id, so copying another database's history would be invalid.
        with monkeypatch.context() as patch:
            patch.setattr(
                SQLiteGovernanceStore, "create", classmethod(lambda cls, *a, **kw: c.store)
            )
            child = runtime_case(durable_workflow=True)
        await decision_ready(child)
        child.experience = capture_service(child).capture(child.incident_id)
        child.evaluator = evaluator(child)
        child.evaluation = child.evaluator.evaluate(child.experience.experience_id)
        migrate_feedback(child.store.database)
        child.feedback_store = FeedbackStore(child.evaluator.store)
        child.boundary = Boundary()
        child.feedback = AnalystFeedbackService(
            child.feedback_store,
            provider=child.boundary.provider,
            provider_id="test-identity",
            permissions=RBACPermissionVerifier(roles=child.boundary.roles),
        )
        request = FeedbackRequest(
            submission_id=uuid4(),
            incident_id=child.incident_id,
            experience_id=child.experience.experience_id,
            experience_digest=content_digest(child.experience),
            evaluation_id=child.evaluation.evaluation_id,
            evaluation_digest=content_digest(child.evaluation),
            verdict=Verdict.CORRECT,
            coverage_expectation=CoverageExpectation(
                required_permissions=(ToolPermission.NETWORK_READ,)
            ),
        )
        feedback = child.feedback.submit(request, credential=issue(child, request))
        c.holdout_feedback.append(feedback)
        c.children.append(child)
        evaluation_ids.append(child.evaluation.evaluation_id)
    migrate_datasets(c.store.database)
    c.datasets = ImprovementDatasetStore(c.feedback_store)
    c.builder = ImprovementDatasetBuilder(c.datasets)
    c.dataset = c.builder.build(evaluation_ids)
    migrate_candidates(c.store.database)
    c.candidates = ImprovementCandidateStore(c.datasets)
    c.improvement = ImprovementCandidateService(c.candidates)
    generated = c.improvement.propose(c.dataset.dataset_id)
    c.review = next(
        candidate
        for candidate in generated.candidates
        if candidate.content.candidate_type == CandidateType.INVESTIGATION_STRATEGY
    )
    c.candidate = c.candidates.declare_coverage_proposal(
        c.review.candidate_id, required_permission=ToolPermission.NETWORK_READ
    )
    migrate_offline_evaluation(c.store.database)
    c.offline = OfflineEvaluationStore(c.candidates)
    with c.store.database.transaction(write=False) as connection:
        binding, facts = c.candidates._context(connection, c.dataset.dataset_id)
    # Fixture-only ID-based configuration choice for a nonempty multi-case holdout.
    # No metric or observed baseline/candidate outcome is used to choose membership.
    config = next(
        SplitConfig(bucket_count=n, holdout_buckets=n - 1)
        for n in range(2, 32)
        if len(
            partition(
                binding,
                facts,
                c.candidate.content.supporting_sample_refs,
                SplitConfig(bucket_count=n, holdout_buckets=n - 1),
            ).content.holdout
        )
        >= 2
    )
    c.offline_planner = OfflineEvaluationPlanner(c.offline, split_config=config)
    c.planning = c.offline_planner.plan(c.candidate.candidate_id)
    c.plan = c.planning.test_plan
    migrate_offline_comparison(c.store.database)
    migrate_frozen_baselines(c.store.database)
    c.comparison_store = OfflineComparisonStore(c.offline)
    c.baseline = c.comparison_store.capture_baseline(
        target_reference="soc_agent.planning.models.PlannerInput",
        configuration=CoverageConfiguration(covered_permissions=(ToolPermission.SYSTEM_READ,)),
    )
    c.runner = OfflineEvaluationRunner(c.comparison_store)
    return c
