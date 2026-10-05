"""Explicit SPECIFY -> PLAN -> STOP, without variant creation or evaluation."""

from soc_agent.offline_evaluation.models import PlanningResult, SplitConfig
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.offline_evaluation.store import OfflineEvaluationStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


class OfflineEvaluationPlanner:
    def __init__(
        self,
        store: OfflineEvaluationStore,
        *,
        split_config: SplitConfig | None = None,
    ) -> None:
        self.store = store
        self.split_config = SplitConfig.model_validate((split_config or SplitConfig()).model_dump())

    def plan(
        self,
        candidate_id: str,
        *,
        expected_candidate_digest: str | None = None,
        expected_manifest_digest: str | None = None,
    ) -> PlanningResult:
        with self.store.database.transaction() as connection:
            candidate, facts = self.store._source(connection, candidate_id)
            if expected_candidate_digest is not None and (
                content_digest(candidate.content) != expected_candidate_digest
            ):
                raise StoredDataError("Requested candidate content digest mismatch")
            if expected_manifest_digest is not None and (
                candidate.content.dataset.manifest_digest != expected_manifest_digest
            ):
                raise StoredDataError("Requested dataset manifest mismatch")
            specification = self.store._insert_specification(
                connection,
                specify(candidate, facts, self.split_config),
            )
            test_plan = self.store._insert_plan(connection, make_test_plan(specification))
            return PlanningResult(specification=specification, test_plan=test_plan)
