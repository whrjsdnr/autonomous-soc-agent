"""Validate -> explicit offline replay or unavailable result -> compare -> STOP."""

from soc_agent.offline_comparison.models import EXEC_EVALUATOR_VERSION, EvaluationArtifacts
from soc_agent.offline_comparison.store import OfflineComparisonStore


class OfflineEvaluationRunner:
    def __init__(self, store: OfflineComparisonStore) -> None:
        self.store = store

    def evaluate(
        self,
        plan_id: str,
        *,
        expected_plan_digest: str | None = None,
        baseline_id: str | None = None,
        expected_baseline_digest: str | None = None,
        evaluator_version: str = EXEC_EVALUATOR_VERSION,
    ) -> EvaluationArtifacts:
        with self.store.database.transaction() as connection:
            expected = self.store._expected(
                connection,
                plan_id,
                baseline_id,
                expected_plan_digest=expected_plan_digest,
                expected_baseline_digest=expected_baseline_digest,
                evaluator_version=evaluator_version,
            )
            cache = {(plan_id, baseline_id, evaluator_version): expected}
            variant = self.store._insert(
                connection, "offline_candidate_variants", expected.variant, expected_cache=cache
            )
            baseline = self.store._insert(
                connection,
                "offline_evaluation_results",
                expected.baseline_result,
                expected_cache=cache,
            )
            candidate = self.store._insert(
                connection,
                "offline_evaluation_results",
                expected.candidate_result,
                expected_cache=cache,
            )
            comparison = self.store._insert(
                connection, "offline_comparisons", expected.comparison, expected_cache=cache
            )
            return EvaluationArtifacts(
                variant=variant,
                baseline_result=baseline,
                candidate_result=candidate,
                comparison=comparison,
            )
