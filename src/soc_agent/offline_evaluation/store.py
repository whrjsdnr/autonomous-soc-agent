"""Immutable planning queries with full durable source-graph revalidation."""

from sqlite3 import Connection, Row

from soc_agent.improvement_candidates.models import ImprovementCandidate, SampleFacts
from soc_agent.improvement_candidates.store import ImprovementCandidateStore
from soc_agent.offline_evaluation.models import CandidateTestPlan, EvaluationSpecification
from soc_agent.offline_evaluation.planning import make_test_plan, specify
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError

Source = tuple[ImprovementCandidate, tuple[SampleFacts, ...]]


class OfflineEvaluationStore:
    def __init__(self, candidates: ImprovementCandidateStore) -> None:
        self.candidates = candidates
        self.database = candidates.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (10, 11, 12):
                raise UnsupportedSchemaError("Explicit offline evaluation migration required")
            connection.execute(
                "SELECT specification_id FROM offline_evaluation_specifications LIMIT 0"
            )
            connection.execute("SELECT plan_id FROM candidate_test_plans LIMIT 0")

    def _source(self, connection: Connection, candidate_id: str) -> Source:
        row = connection.execute(
            "SELECT * FROM improvement_candidates WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown planning candidate")
        context = self.candidates._context(connection, row["dataset_id"])
        candidate = self.candidates._candidate(connection, row, context)
        return candidate, context[1]

    def _specification(self, connection: Connection, row: Row) -> EvaluationSpecification:
        value = ledger.decode(EvaluationSpecification, row)
        binding = value.content.binding
        if (value.specification_id, binding.candidate.identity) != (
            row["specification_id"],
            row["candidate_id"],
        ):
            raise StoredDataError("Specification indexed binding mismatch")
        candidate, facts = self._source(connection, binding.candidate.identity)
        expected = specify(candidate, facts, value.content.partition.content.config)
        if expected.content != value.content:
            raise StoredDataError("Specification does not match pinned candidate and dataset")
        return value

    def _plan(self, connection: Connection, row: Row) -> CandidateTestPlan:
        value = ledger.decode(CandidateTestPlan, row)
        c = value.content
        if (value.plan_id, c.specification.identity, c.binding.candidate.identity) != (
            row["plan_id"],
            row["specification_id"],
            row["candidate_id"],
        ):
            raise StoredDataError("Test plan indexed binding mismatch")
        spec_row = connection.execute(
            "SELECT * FROM offline_evaluation_specifications WHERE specification_id=?",
            (c.specification.identity,),
        ).fetchone()
        if spec_row is None:
            raise StoredDataError("Test plan specification missing")
        specification = self._specification(connection, spec_row)
        if c != make_test_plan(specification).content:
            raise StoredDataError("Test plan does not match its specification")
        return value

    def _insert_specification(
        self,
        connection: Connection,
        value: EvaluationSpecification,
    ) -> EvaluationSpecification:
        row = connection.execute(
            "SELECT * FROM offline_evaluation_specifications WHERE specification_id=?",
            (value.specification_id,),
        ).fetchone()
        if row is not None:
            old = self._specification(connection, row)
            if old.content != value.content:
                raise StoredDataError("Conflicting specification identity")
            return old
        connection.execute(
            "INSERT INTO offline_evaluation_specifications VALUES (?,?,?,?)",
            (
                value.specification_id,
                value.content.binding.candidate.identity,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def _insert_plan(self, connection: Connection, value: CandidateTestPlan) -> CandidateTestPlan:
        row = connection.execute(
            "SELECT * FROM candidate_test_plans WHERE plan_id=?",
            (value.plan_id,),
        ).fetchone()
        if row is not None:
            old = self._plan(connection, row)
            if old.content != value.content:
                raise StoredDataError("Conflicting test plan identity")
            return old
        connection.execute(
            "INSERT INTO candidate_test_plans VALUES (?,?,?,?,?)",
            (
                value.plan_id,
                value.content.specification.identity,
                value.content.binding.candidate.identity,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def get_specification(self, specification_id: str) -> EvaluationSpecification:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM offline_evaluation_specifications WHERE specification_id=?",
                (specification_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown evaluation specification")
            return self._specification(connection, row)

    def list_specifications(self, candidate_id: str) -> tuple[EvaluationSpecification, ...]:
        with self.database.transaction(write=False) as connection:
            self._source(connection, candidate_id)
            return tuple(
                self._specification(connection, row)
                for row in connection.execute(
                    "SELECT * FROM offline_evaluation_specifications WHERE candidate_id=? "
                    "ORDER BY specification_id",
                    (candidate_id,),
                )
            )

    def get_test_plan(self, plan_id: str) -> CandidateTestPlan:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM candidate_test_plans WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown candidate test plan")
            return self._plan(connection, row)

    def list_test_plans(self, candidate_id: str) -> tuple[CandidateTestPlan, ...]:
        with self.database.transaction(write=False) as connection:
            self._source(connection, candidate_id)
            return tuple(
                self._plan(connection, row)
                for row in connection.execute(
                    "SELECT * FROM candidate_test_plans WHERE candidate_id=? ORDER BY plan_id",
                    (candidate_id,),
                )
            )
