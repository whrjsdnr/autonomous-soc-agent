"""Canonical immutable dataset queries and export; pinned snapshots never absorb new feedback."""

from sqlite3 import Connection, Row

from soc_agent.feedback.models import DiagnosticLabel, Verdict
from soc_agent.feedback.store import FeedbackStore
from soc_agent.improvement_dataset.models import (
    DatasetExport,
    DatasetStatistics,
    EligibilityReason,
    ImprovementDataset,
    ImprovementSample,
)
from soc_agent.improvement_dataset.selection import load_sources, select
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class ImprovementDatasetStore:
    def __init__(self, feedback: FeedbackStore) -> None:
        self.feedback = feedback
        self.database = feedback.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (8, 9, 10, 11, 12):
                raise UnsupportedSchemaError("Explicit dataset migration required")
            for table in (
                "improvement_samples",
                "improvement_datasets",
                "dataset_sample_membership",
            ):
                connection.execute(f"SELECT * FROM {table} LIMIT 0")

    def _sample(self, connection: Connection, sample_id: str) -> ImprovementSample:
        row = connection.execute(
            "SELECT * FROM improvement_samples WHERE sample_id=?", (sample_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown dataset sample")
        value = ledger.decode(ImprovementSample, row)
        if (
            value.sample_id != row["sample_id"]
            or value.content.sources.evaluation.identity != row["evaluation_id"]
        ):
            raise StoredDataError("Sample indexed bindings mismatch")
        sources = value.content.sources
        _, expected = select(
            *load_sources(connection, self.feedback, sources.evaluation.identity, pinned=sources)
        )
        if expected != value:
            raise StoredDataError("Sample does not match pinned sources")
        return value

    def _decode(self, connection: Connection, row: Row) -> ImprovementDataset:
        value = ledger.decode(ImprovementDataset, row)
        if value.dataset_id != row["dataset_id"]:
            raise StoredDataError("Dataset indexed binding mismatch")
        for selection in value.manifest.selection:
            sources = selection.sources
            expected, _ = select(
                *load_sources(
                    connection, self.feedback, sources.evaluation.identity, pinned=sources
                )
            )
            if expected != selection:
                raise StoredDataError("Stored eligibility does not match pinned sources")
        members = connection.execute(
            "SELECT sample_id,position FROM dataset_sample_membership "
            "WHERE dataset_id=? ORDER BY position",
            (value.dataset_id,),
        ).fetchall()
        if [(r["sample_id"], r["position"]) for r in members] != [
            (ref.identity, position) for position, ref in enumerate(value.manifest.samples)
        ]:
            raise StoredDataError("Dataset membership mismatch")
        for ref in value.manifest.samples:
            if content_digest(self._sample(connection, ref.identity)) != ref.digest:
                raise StoredDataError("Dataset sample digest mismatch")
        return value

    def _insert(
        self,
        connection: Connection,
        dataset: ImprovementDataset,
        samples: tuple[ImprovementSample, ...],
    ) -> ImprovementDataset:
        row = connection.execute(
            "SELECT * FROM improvement_datasets WHERE dataset_id=?", (dataset.dataset_id,)
        ).fetchone()
        if row is not None:
            old = self._decode(connection, row)
            if old.manifest != dataset.manifest:
                raise StoredDataError("Conflicting dataset identity")
            return old
        for sample in samples:
            row = connection.execute(
                "SELECT * FROM improvement_samples WHERE sample_id=?", (sample.sample_id,)
            ).fetchone()
            if row is not None:
                if self._sample(connection, sample.sample_id) != sample:
                    raise StoredDataError("Conflicting sample identity")
            else:
                connection.execute(
                    "INSERT INTO improvement_samples VALUES (?,?,?,?)",
                    (
                        sample.sample_id,
                        sample.content.sources.evaluation.identity,
                        ledger.serialize(sample),
                        content_digest(sample),
                    ),
                )
        connection.execute(
            "INSERT INTO improvement_datasets VALUES (?,?,?)",
            (
                dataset.dataset_id,
                ledger.serialize(dataset),
                content_digest(dataset),
            ),
        )
        connection.executemany(
            "INSERT INTO dataset_sample_membership VALUES (?,?,?)",
            (
                (dataset.dataset_id, ref.identity, position)
                for position, ref in enumerate(dataset.manifest.samples)
            ),
        )
        return dataset

    def _get(self, connection: Connection, dataset_id: str) -> ImprovementDataset:
        row = connection.execute(
            "SELECT * FROM improvement_datasets WHERE dataset_id=?", (dataset_id,)
        ).fetchone()
        if row is None:
            raise StoredDataError("Unknown dataset")
        return self._decode(connection, row)

    def get_dataset(self, dataset_id: str) -> ImprovementDataset:
        with self.database.transaction(write=False) as connection:
            return self._get(connection, dataset_id)

    def list_datasets(self) -> tuple[ImprovementDataset, ...]:
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._decode(connection, row)
                for row in connection.execute(
                    "SELECT * FROM improvement_datasets ORDER BY dataset_id"
                )
            )

    def get_sample(self, sample_id: str) -> ImprovementSample:
        with self.database.transaction(write=False) as connection:
            return self._sample(connection, sample_id)

    def list_samples(self, dataset_id: str) -> tuple[ImprovementSample, ...]:
        with self.database.transaction(write=False) as connection:
            value = self._get(connection, dataset_id)
            return tuple(self._sample(connection, ref.identity) for ref in value.manifest.samples)

    def export_json(self, dataset_id: str) -> str:
        """Canonical JSON in manifest order, no nondeterministic creation-time metadata."""
        with self.database.transaction(write=False) as connection:
            value = self._get(connection, dataset_id)
            export = DatasetExport(
                dataset_id=value.dataset_id,
                dataset_version=value.dataset_version,
                manifest_digest=value.manifest_digest,
                manifest=value.manifest,
                samples=tuple(self._sample(connection, r.identity) for r in value.manifest.samples),
            )
            return ledger.serialize(export)

    def statistics(self, dataset_id: str) -> DatasetStatistics:
        with self.database.transaction(write=False) as connection:
            value = self._get(connection, dataset_id)
            samples = tuple(
                self._sample(connection, ref.identity) for ref in value.manifest.samples
            )
            return DatasetStatistics(
                sample_count=len(samples),
                correct_count=sum(s.content.verdict == Verdict.CORRECT for s in samples),
                incorrect_count=sum(s.content.verdict == Verdict.INCORRECT for s in samples),
                false_positive_count=sum(
                    DiagnosticLabel.FALSE_POSITIVE in s.content.labels for s in samples
                ),
                false_negative_count=sum(
                    DiagnosticLabel.FALSE_NEGATIVE in s.content.labels for s in samples
                ),
                exclusion_count=value.manifest.excluded_count,
                disagreement_count=sum(
                    s.reason == EligibilityReason.ANALYST_DISAGREEMENT
                    for s in value.manifest.selection
                ),
            )
