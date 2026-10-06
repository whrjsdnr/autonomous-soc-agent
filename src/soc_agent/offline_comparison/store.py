"""Immutable offline ledger with snapshot replay validation; no production executor."""

from sqlite3 import Connection, Row

from soc_agent.improvement_candidates.models import SampleFacts
from soc_agent.offline_comparison.coverage_models import (
    TARGET_REFERENCE,
    BaselineContent,
    CoverageConfiguration,
    CoverageGroundTruth,
    FrozenBaseline,
)
from soc_agent.offline_comparison.evaluation import evaluate_unavailable
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import (
    EvaluationArtifacts,
    OfflineCandidateVariant,
    OfflineComparison,
    OfflineEvaluationResult,
)
from soc_agent.offline_evaluation.store import OfflineEvaluationStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.tools.enums import ToolPermission

Artifact = OfflineCandidateVariant | OfflineEvaluationResult | OfflineComparison
TABLES = {
    "offline_candidate_variants": OfflineCandidateVariant,
    "offline_evaluation_results": OfflineEvaluationResult,
    "offline_comparisons": OfflineComparison,
}


def identity(value: Artifact) -> str:
    if isinstance(value, OfflineCandidateVariant):
        return value.variant_id
    if isinstance(value, OfflineEvaluationResult):
        return value.result_id
    return value.comparison_id


class OfflineComparisonStore:
    def __init__(self, planning: OfflineEvaluationStore) -> None:
        self.planning = planning
        self.database = planning.database
        with self.database.transaction(write=False) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (11, 12, 13):
                raise UnsupportedSchemaError("Explicit offline comparison migration required")
            if version in (12, 13):
                connection.execute("SELECT baseline_id FROM frozen_offline_baselines LIMIT 0")
            for table in TABLES:
                connection.execute(f"SELECT id FROM {table} LIMIT 0")

    def _baseline(self, connection: Connection, baseline_id: str) -> FrozenBaseline:
        if connection.execute("PRAGMA user_version").fetchone()[0] not in (12, 13):
            raise UnsupportedSchemaError("Explicit frozen baseline migration required")
        row = connection.execute(
            "SELECT * FROM frozen_offline_baselines WHERE baseline_id=?", (baseline_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown frozen baseline")
        value = ledger.decode(FrozenBaseline, row)
        if (value.baseline_id, value.content.target_reference) != (
            row["baseline_id"],
            row["target_reference"],
        ):
            raise StoredDataError("Frozen baseline indexed binding mismatch")
        return value

    def capture_baseline(
        self, *, target_reference: str, configuration: CoverageConfiguration
    ) -> FrozenBaseline:
        """Explicit offline configuration capture; never infer production/historical state."""
        if target_reference != TARGET_REFERENCE:
            raise ValueError("Target has no supported deterministic offline baseline contract")
        configuration = CoverageConfiguration.model_validate(configuration.model_dump())
        content = BaselineContent(configuration=configuration)
        digest = content_digest(content)
        value = FrozenBaseline(baseline_id=digest, baseline_version=digest, content=content)
        with self.database.transaction() as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (12, 13):
                raise UnsupportedSchemaError("Explicit frozen baseline migration required")
            row = connection.execute(
                "SELECT * FROM frozen_offline_baselines WHERE baseline_id=?", (digest,)
            ).fetchone()
            if row is not None:
                old = self._baseline(connection, digest)
                if old.content != content:
                    raise StoredDataError("Conflicting frozen baseline identity")
                return old
            connection.execute(
                "INSERT INTO frozen_offline_baselines VALUES (?,?,?,?)",
                (digest, target_reference, ledger.serialize(value), content_digest(value)),
            )
        return value

    def get_baseline(self, baseline_id: str) -> FrozenBaseline:
        with self.database.transaction(write=False) as connection:
            return self._baseline(connection, baseline_id)

    def _ground_truth(
        self, connection: Connection, facts: tuple[SampleFacts, ...]
    ) -> dict[str, CoverageGroundTruth]:
        truths = {}
        feedback_store = self.planning.candidates.datasets.feedback
        for fact in facts:
            requirements: set[ToolPermission] = set()
            refs = []
            for ref in fact.sources.feedback:
                row = connection.execute(
                    "SELECT * FROM analyst_feedback WHERE feedback_id=?", (ref.identity,)
                ).fetchone()
                if row is None:
                    raise StoredDataError("Missing holdout feedback")
                feedback = feedback_store._decode(connection, row)
                if content_digest(feedback) != ref.digest:
                    raise StoredDataError("Holdout ground-truth feedback digest mismatch")
                request = feedback.request
                if (
                    request.incident_id,
                    request.experience_id,
                    request.experience_digest,
                    request.evaluation_id,
                    request.evaluation_digest,
                ) != (
                    fact.sources.incident_id,
                    fact.sources.experience.identity,
                    fact.sources.experience.digest,
                    fact.sources.evaluation.identity,
                    fact.sources.evaluation.digest,
                ):
                    raise StoredDataError("Foreign human coverage ground truth")
                expectation = request.coverage_expectation
                if expectation is not None:
                    requirements.update(expectation.required_permissions)
                    refs.append(ref)
            truths[fact.sample.identity] = CoverageGroundTruth(
                status="MEASURABLE" if refs else "NOT_MEASURABLE",
                required_permissions=tuple(sorted(requirements)),
                feedback_refs=tuple(refs),
            )
        return truths

    def _expected(
        self,
        connection: Connection,
        plan_id: str,
        baseline_id: str | None = None,
        *,
        expected_plan_digest: str | None = None,
        expected_baseline_digest: str | None = None,
    ) -> EvaluationArtifacts:
        row = connection.execute(
            "SELECT * FROM candidate_test_plans WHERE plan_id=?", (plan_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown offline test plan")
        plan = self.planning._plan(connection, row)
        if (
            expected_plan_digest is not None
            and content_digest(plan.content) != expected_plan_digest
        ):
            raise StoredDataError("Requested test plan digest mismatch")
        spec_row = connection.execute(
            "SELECT * FROM offline_evaluation_specifications WHERE specification_id=?",
            (plan.content.specification.identity,),
        ).fetchone()
        specification = self.planning._specification(connection, spec_row)
        source, facts = self.planning._source(connection, plan.content.binding.candidate.identity)
        if baseline_id is None:
            if expected_baseline_digest is not None:
                raise StoredDataError("Requested frozen baseline missing")
            return evaluate_unavailable(source, specification, plan, facts)
        baseline = self._baseline(connection, baseline_id)
        if expected_baseline_digest is not None and (
            content_digest(baseline.content) != expected_baseline_digest
        ):
            raise StoredDataError("Requested frozen baseline digest mismatch")
        holdout = {ref.identity for ref in specification.content.partition.content.holdout}
        truths = self._ground_truth(
            connection, tuple(f for f in facts if f.sample.identity in holdout)
        )
        return execute_pair(source, specification, plan, facts, baseline, truths)

    def _decode(
        self,
        connection: Connection,
        table: str,
        row: Row,
        *,
        expected_cache: dict[tuple[str, str | None], EvaluationArtifacts] | None = None,
    ) -> Artifact:
        value = ledger.decode(TABLES[table], row)
        binding = value.content.binding
        if (identity(value), binding.test_plan.identity, binding.source.candidate.identity) != (
            row["id"],
            row["plan_id"],
            row["candidate_id"],
        ):
            raise StoredDataError("Offline artifact indexed binding mismatch")
        # Cache only within this SQLite transaction's immutable source snapshot;
        # every persisted parent still gets checksum, index and semantic validation.
        if expected_cache is None:
            expected_cache = {}
        key = (
            row["plan_id"],
            binding.frozen_baseline.identity if binding.frozen_baseline is not None else None,
        )
        if key not in expected_cache:
            expected_cache[key] = self._expected(connection, *key)
        expected = expected_cache[key]
        options = (
            expected.variant,
            expected.baseline_result,
            expected.candidate_result,
            expected.comparison,
        )
        if not any(type(v) is type(value) and v.content == value.content for v in options):
            raise StoredDataError("Offline artifact does not match frozen inputs")
        parents = []
        if isinstance(value, OfflineEvaluationResult) and value.content.variant is not None:
            parents.append(("offline_candidate_variants", value.content.variant))
        if isinstance(value, OfflineComparison):
            parents.extend(
                ("offline_evaluation_results", ref)
                for ref in (value.content.baseline_result, value.content.candidate_result)
            )
        for parent_table, ref in parents:
            parent_row = connection.execute(
                f"SELECT * FROM {parent_table} WHERE id=?", (ref.identity,)
            ).fetchone()
            if parent_row is None:
                raise StoredDataError("Missing pinned offline artifact")
            parent = self._decode(
                connection, parent_table, parent_row, expected_cache=expected_cache
            )
            if content_digest(parent.content) != ref.digest:
                raise StoredDataError("Pinned offline artifact digest mismatch")
        return value

    def _insert(
        self,
        connection: Connection,
        table: str,
        value: Artifact,
        *,
        expected_cache: dict[tuple[str, str | None], EvaluationArtifacts] | None = None,
    ) -> Artifact:
        row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (identity(value),)).fetchone()
        if row is not None:
            existing = self._decode(connection, table, row, expected_cache=expected_cache)
            if existing.content != value.content:
                raise StoredDataError("Conflicting offline artifact identity")
            return existing
        binding = value.content.binding
        connection.execute(
            f"INSERT INTO {table} VALUES (?,?,?,?,?)",
            (
                identity(value),
                binding.test_plan.identity,
                binding.source.candidate.identity,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def _get(self, table: str, artifact_id: str) -> Artifact:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (artifact_id,)).fetchone()
            if row is None:
                raise StoredDataError("Unknown offline artifact")
            return self._decode(connection, table, row)

    def _list(self, table: str, candidate_id: str) -> tuple[Artifact, ...]:
        with self.database.transaction(write=False) as connection:
            self.planning._source(connection, candidate_id)
            cache: dict[tuple[str, str | None], EvaluationArtifacts] = {}
            return tuple(
                self._decode(connection, table, row, expected_cache=cache)
                for row in connection.execute(
                    f"SELECT * FROM {table} WHERE candidate_id=? ORDER BY id", (candidate_id,)
                )
            )

    def get_variant(self, variant_id: str) -> OfflineCandidateVariant:
        value = self._get("offline_candidate_variants", variant_id)
        assert isinstance(value, OfflineCandidateVariant)
        return value

    def list_variants(self, candidate_id: str) -> tuple[OfflineCandidateVariant, ...]:
        return tuple(
            v
            for v in self._list("offline_candidate_variants", candidate_id)
            if isinstance(v, OfflineCandidateVariant)
        )

    def get_evaluation_result(self, result_id: str) -> OfflineEvaluationResult:
        value = self._get("offline_evaluation_results", result_id)
        assert isinstance(value, OfflineEvaluationResult)
        return value

    def list_results(self, candidate_id: str) -> tuple[OfflineEvaluationResult, ...]:
        return tuple(
            v
            for v in self._list("offline_evaluation_results", candidate_id)
            if isinstance(v, OfflineEvaluationResult)
        )

    def get_comparison(self, comparison_id: str) -> OfflineComparison:
        value = self._get("offline_comparisons", comparison_id)
        assert isinstance(value, OfflineComparison)
        return value

    def list_comparisons(self, candidate_id: str) -> tuple[OfflineComparison, ...]:
        return tuple(
            v
            for v in self._list("offline_comparisons", candidate_id)
            if isinstance(v, OfflineComparison)
        )
