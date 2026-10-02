"""Canonical historical evaluation queries; no operation uses evaluations as authority."""

from sqlite3 import Connection, Row
from uuid import UUID

from soc_agent.evaluation.models import EVALUATOR_VERSION, EvaluationRecord
from soc_agent.experience.store import ExperienceStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class EvaluationStore:
    def __init__(self, experiences: ExperienceStore) -> None:
        self.experiences = experiences
        self.database = experiences.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (6, 7):
                raise UnsupportedSchemaError("Explicit evaluation migration required")
            connection.execute("SELECT evaluation_id FROM evaluations LIMIT 0")

    def _decode(self, connection: Connection, row: Row) -> EvaluationRecord:
        value = ledger.decode(EvaluationRecord, row)
        c = value.content
        if (value.evaluation_id, c.experience_id, str(c.incident_id), c.evaluator_version) != (
            row["evaluation_id"],
            row["experience_id"],
            row["incident_id"],
            row["evaluator_version"],
        ):
            raise StoredDataError("Evaluation indexed binding mismatch")
        source = connection.execute(
            "SELECT * FROM experiences WHERE experience_id=?",
            (c.experience_id,),
        ).fetchone()
        if source is None:
            raise StoredDataError("Evaluation source is missing")
        experience = self.experiences._decode(source)
        if (
            content_digest(experience),
            experience.content.incident_id,
            experience.content.run_id,
        ) != (
            c.experience_digest,
            c.incident_id,
            c.run_id,
        ):
            raise StoredDataError("Evaluation source binding mismatch")
        return value

    def _insert(self, connection: Connection, value: EvaluationRecord) -> EvaluationRecord:
        c = value.content
        row = connection.execute(
            "SELECT * FROM evaluations WHERE experience_id=? AND evaluator_version=?",
            (c.experience_id, c.evaluator_version),
        ).fetchone()
        if row is not None:
            previous = self._decode(connection, row)
            if previous.content != c:
                raise StoredDataError("Conflicting logical evaluation")
            return previous
        connection.execute(
            "INSERT INTO evaluations VALUES (?,?,?,?,?,?)",
            (
                value.evaluation_id,
                c.experience_id,
                str(c.incident_id),
                c.evaluator_version,
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def get(self, evaluation_id: str) -> EvaluationRecord:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM evaluations WHERE evaluation_id=?",
                (evaluation_id,),
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown evaluation")
            return self._decode(connection, row)

    def get_for_experience(self, experience_id: str) -> EvaluationRecord | None:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM evaluations WHERE experience_id=? AND evaluator_version=?",
                (experience_id, EVALUATOR_VERSION),
            ).fetchone()
            return self._decode(connection, row) if row is not None else None

    def list_for_incident(self, incident_id: UUID) -> tuple[EvaluationRecord, ...]:
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._decode(connection, row)
                for row in connection.execute(
                    "SELECT * FROM evaluations WHERE incident_id=? ORDER BY evaluation_id",
                    (str(incident_id),),
                )
            )
