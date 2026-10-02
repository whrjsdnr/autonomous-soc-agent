"""Explicit offline LEARN -> PROPOSE -> STOP. No runtime integration."""

from collections.abc import Iterable

from soc_agent.improvement_candidates.analysis import analyze
from soc_agent.improvement_candidates.generation import generate
from soc_agent.improvement_candidates.models import (
    AnalysisConfig,
    FailurePattern,
    ImprovementCandidate,
    ProposalResult,
)
from soc_agent.improvement_candidates.store import Context, ImprovementCandidateStore
from soc_agent.review.persistence.models import StoredDataError


class ImprovementCandidateService:
    def __init__(
        self,
        store: ImprovementCandidateStore,
        *,
        config: AnalysisConfig | None = None,
    ) -> None:
        self.store = store
        self.config = AnalysisConfig.model_validate((config or AnalysisConfig()).model_dump())

    def _check(self, context: Context, expected_manifest_digest: str | None) -> None:
        if expected_manifest_digest is not None and (
            context[0].manifest_digest != expected_manifest_digest
        ):
            raise StoredDataError("Requested dataset manifest mismatch")

    def analyze(
        self,
        dataset_id: str,
        *,
        expected_manifest_digest: str | None = None,
    ) -> tuple[FailurePattern, ...]:
        with self.store.database.transaction() as connection:
            context = self.store._context(connection, dataset_id)
            self._check(context, expected_manifest_digest)
            return tuple(
                self.store._insert_pattern(connection, p, context)
                for p in analyze(*context, self.config)
            )

    def generate(
        self,
        dataset_id: str,
        pattern_ids: Iterable[str],
    ) -> tuple[ImprovementCandidate, ...]:
        with self.store.database.transaction() as connection:
            context = self.store._context(connection, dataset_id)
            candidates = []
            for identity in sorted(set(pattern_ids)):
                row = connection.execute(
                    "SELECT * FROM failure_patterns WHERE pattern_id=?",
                    (identity,),
                ).fetchone()
                if row is None:
                    raise StoredDataError("Unknown generation pattern")
                pattern = self.store._pattern(connection, row, context)
                candidates.extend(
                    self.store._insert_candidate(connection, c, context) for c in generate(pattern)
                )
            return tuple(sorted(candidates, key=lambda c: c.candidate_id))

    def propose(
        self,
        dataset_id: str,
        *,
        expected_manifest_digest: str | None = None,
    ) -> ProposalResult:
        with self.store.database.transaction() as connection:
            context = self.store._context(connection, dataset_id)
            self._check(context, expected_manifest_digest)
            patterns = tuple(
                self.store._insert_pattern(connection, p, context)
                for p in analyze(*context, self.config)
            )
            candidates = tuple(
                sorted(
                    (
                        self.store._insert_candidate(connection, c, context)
                        for pattern in patterns
                        for c in generate(pattern)
                    ),
                    key=lambda c: c.candidate_id,
                )
            )
            return ProposalResult(patterns=patterns, candidates=candidates)
