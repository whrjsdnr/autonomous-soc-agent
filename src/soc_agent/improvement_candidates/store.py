"""Durable offline queries; every artifact is checked against pinned historical facts."""

from sqlite3 import Connection, Row

from soc_agent.improvement_candidates.analysis import analyze
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_candidates.models import (
    CandidateType,
    CandidateTypeCount,
    DatasetBinding,
    FailurePattern,
    ImprovementCandidate,
    ImprovementStatistics,
    SampleFacts,
)
from soc_agent.improvement_dataset.store import ImprovementDatasetStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError

Context = tuple[DatasetBinding, tuple[SampleFacts, ...]]


class ImprovementCandidateStore:
    def __init__(self, datasets: ImprovementDatasetStore) -> None:
        self.datasets = datasets
        self.database = datasets.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (9, 10):
                raise UnsupportedSchemaError("Explicit candidate migration required")
            connection.execute("SELECT pattern_id FROM failure_patterns LIMIT 0")
            connection.execute("SELECT candidate_id FROM improvement_candidates LIMIT 0")

    def _context(self, connection: Connection, dataset_id: str) -> Context:
        value = self.datasets._get(connection, dataset_id)
        binding = DatasetBinding(
            dataset_id=value.dataset_id,
            dataset_version=value.dataset_version,
            manifest_digest=value.manifest_digest,
        )
        facts = []
        for ref in value.manifest.samples:
            sample = self.datasets._sample(connection, ref.identity)
            sources = sample.content.sources
            row = connection.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=?",
                (sources.evaluation.identity,),
            ).fetchone()
            evaluation = self.datasets.feedback.evaluations._decode(connection, row)
            if content_digest(evaluation) != sources.evaluation.digest:
                raise StoredDataError("Analysis evaluation reference mismatch")
            e = evaluation.content
            facts.append(
                SampleFacts(
                    sample=ref,
                    sources=sources,
                    verdict=sample.content.verdict,
                    labels=sample.content.labels,
                    objective=sample.content.objective,
                    recovery_observed=e.recovery_observed,
                    uncertain_observed=e.uncertain_observed,
                    reconciliation_observed=e.reconciliation_observed,
                )
            )
        return binding, tuple(facts)

    def _pattern(self, connection: Connection, row: Row, context: Context) -> FailurePattern:
        value = ledger.decode(FailurePattern, row)
        if (value.pattern_id, value.content.dataset.dataset_id) != (
            row["pattern_id"],
            row["dataset_id"],
        ) or value.content.dataset != context[0]:
            raise StoredDataError("Pattern dataset/index binding mismatch")
        expected = analyze(*context, value.content.config)
        if not any(p.content == value.content for p in expected):
            raise StoredDataError("Pattern does not match dataset facts")
        return value

    def _candidate(
        self,
        connection: Connection,
        row: Row,
        context: Context,
    ) -> ImprovementCandidate:
        value = ledger.decode(ImprovementCandidate, row)
        c = value.content
        (ref,) = c.failure_pattern_refs
        if (value.candidate_id, c.dataset.dataset_id, ref.identity, c.candidate_type.value) != (
            row["candidate_id"],
            row["dataset_id"],
            row["pattern_id"],
            row["candidate_type"],
        ) or c.dataset != context[0]:
            raise StoredDataError("Candidate dataset/index binding mismatch")
        pattern_row = connection.execute(
            "SELECT * FROM failure_patterns WHERE pattern_id=?",
            (ref.identity,),
        ).fetchone()
        if pattern_row is None:
            raise StoredDataError("Candidate pattern missing")
        pattern = self._pattern(connection, pattern_row, context)
        if ref.digest != content_digest(pattern.content):
            raise StoredDataError("Candidate pattern digest mismatch")
        if not any(candidate.content == c for candidate in generate(pattern)):
            raise StoredDataError("Candidate does not match its supporting pattern")
        return value

    def _insert_pattern(
        self,
        connection: Connection,
        value: FailurePattern,
        context: Context,
    ) -> FailurePattern:
        row = connection.execute(
            "SELECT * FROM failure_patterns WHERE pattern_id=?",
            (value.pattern_id,),
        ).fetchone()
        if row is not None:
            old = self._pattern(connection, row, context)
            if old.content != value.content:
                raise StoredDataError("Conflicting pattern identity")
            return old
        connection.execute(
            "INSERT INTO failure_patterns VALUES (?,?,?,?)",
            (
                value.pattern_id,
                value.content.dataset.dataset_id,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def _insert_candidate(
        self,
        connection: Connection,
        value: ImprovementCandidate,
        context: Context,
    ) -> ImprovementCandidate:
        row = connection.execute(
            "SELECT * FROM improvement_candidates WHERE candidate_id=?",
            (value.candidate_id,),
        ).fetchone()
        if row is not None:
            old = self._candidate(connection, row, context)
            if old.content != value.content:
                raise StoredDataError("Conflicting candidate identity")
            return old
        c = value.content
        connection.execute(
            "INSERT INTO improvement_candidates VALUES (?,?,?,?,?,?)",
            (
                value.candidate_id,
                c.dataset.dataset_id,
                c.failure_pattern_refs[0].identity,
                c.candidate_type.value,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def get_pattern(self, pattern_id: str) -> FailurePattern:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM failure_patterns WHERE pattern_id=?",
                (pattern_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown pattern")
            return self._pattern(connection, row, self._context(connection, row["dataset_id"]))

    def list_patterns(self, dataset_id: str) -> tuple[FailurePattern, ...]:
        with self.database.transaction(write=False) as connection:
            context = self._context(connection, dataset_id)
            return tuple(
                self._pattern(connection, row, context)
                for row in connection.execute(
                    "SELECT * FROM failure_patterns WHERE dataset_id=? ORDER BY pattern_id",
                    (dataset_id,),
                )
            )

    def get_candidate(self, candidate_id: str) -> ImprovementCandidate:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM improvement_candidates WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown candidate")
            return self._candidate(connection, row, self._context(connection, row["dataset_id"]))

    def list_candidates(self, dataset_id: str) -> tuple[ImprovementCandidate, ...]:
        with self.database.transaction(write=False) as connection:
            context = self._context(connection, dataset_id)
            return tuple(
                self._candidate(connection, row, context)
                for row in connection.execute(
                    "SELECT * FROM improvement_candidates WHERE dataset_id=? ORDER BY candidate_id",
                    (dataset_id,),
                )
            )

    def statistics(self, dataset_id: str) -> ImprovementStatistics:
        with self.database.transaction(write=False) as connection:
            context = self._context(connection, dataset_id)
            patterns = tuple(
                self._pattern(connection, row, context)
                for row in connection.execute(
                    "SELECT * FROM failure_patterns WHERE dataset_id=? ORDER BY pattern_id",
                    (dataset_id,),
                )
            )
            candidates = tuple(
                self._candidate(connection, row, context)
                for row in connection.execute(
                    "SELECT * FROM improvement_candidates WHERE dataset_id=? ORDER BY candidate_id",
                    (dataset_id,),
                )
            )
            return ImprovementStatistics(
                pattern_count=len(patterns),
                candidate_count=len(candidates),
                candidate_type_counts=tuple(
                    CandidateTypeCount(
                        candidate_type=kind,
                        count=sum(c.content.candidate_type == kind for c in candidates),
                    )
                    for kind in sorted(CandidateType)
                ),
                pattern_support_counts=tuple(
                    (p.pattern_id, p.content.occurrence_count) for p in patterns
                ),
            )
