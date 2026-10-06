"""Safe historical queries and transaction-local canonical insertion."""

from sqlite3 import Connection, Row
from uuid import UUID

from soc_agent.experience.models import Experience
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError


class ExperienceStore:
    def __init__(self, governance: SQLiteGovernanceStore) -> None:
        self.governance = governance
        self.database = governance.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] not in (
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
            ):
                raise UnsupportedSchemaError("Explicit experience migration required")
            connection.execute("SELECT experience_id FROM experiences LIMIT 0")

    @staticmethod
    def _decode(row: Row) -> Experience:
        value = ledger.decode(Experience, row)
        if (value.experience_id, str(value.content.incident_id), str(value.content.run_id)) != (
            row["experience_id"],
            row["incident_id"],
            row["run_id"],
        ):
            raise StoredDataError("Experience columns/content mismatch")
        return value

    def _insert(self, connection: Connection, value: Experience) -> Experience:
        row = connection.execute(
            "SELECT * FROM experiences WHERE experience_id=?", (value.experience_id,)
        ).fetchone()
        if row is not None:
            previous = self._decode(row)
            if previous.content != value.content:
                raise StoredDataError("Conflicting historical content")
            return previous
        connection.execute(
            "INSERT INTO experiences VALUES (?,?,?,?,?)",
            (
                value.experience_id,
                str(value.content.incident_id),
                str(value.content.run_id),
                ledger.serialize(value),
                content_digest(value),
            ),
        )
        return value

    def get(self, experience_id: str) -> Experience:
        with self.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM experiences WHERE experience_id=?", (experience_id,)
            ).fetchone()
            if row is None:
                raise StoredDataError("Unknown experience")
            return self._decode(row)

    def list_for_incident(self, incident_id: UUID) -> tuple[Experience, ...]:
        with self.database.transaction(write=False) as connection:
            return tuple(
                self._decode(row)
                for row in connection.execute(
                    "SELECT * FROM experiences WHERE incident_id=? ORDER BY experience_id",
                    (str(incident_id),),
                )
            )
