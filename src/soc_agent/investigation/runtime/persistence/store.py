"""Durable cursor CAS and trace publication; never holds a DB lock across external work."""

from sqlite3 import Connection
from uuid import UUID, uuid4

from soc_agent.investigation.runtime.persistence.models import (
    StaleCheckpoint,
    WorkflowCheckpoint,
    WorkflowInFlight,
)
from soc_agent.investigation.runtime.trace import OrchestrationTrace, OrchestrationTraceEntry
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.review.validation import checked


class CheckpointStore:
    def __init__(self, governance: SQLiteGovernanceStore) -> None:
        self.governance, self.database = governance, governance.database
        with self.database.transaction(write=False) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 4:
                raise UnsupportedSchemaError("Explicit checkpoint migration required")
            connection.execute("SELECT run_id FROM workflow_checkpoints LIMIT 0")
            connection.execute("SELECT run_id FROM workflow_trace LIMIT 0")

    def _read(
        self, connection: Connection, incident_id: UUID
    ) -> tuple[WorkflowCheckpoint, OrchestrationTrace, str | None]:
        row = connection.execute(
            "SELECT * FROM workflow_checkpoints WHERE incident_id=?", (str(incident_id),)
        ).fetchone()
        if row is None:
            raise StoredDataError("No registered workflow checkpoint")
        checkpoint = ledger.decode(WorkflowCheckpoint, row)
        if (
            str(checkpoint.incident_id) != row["incident_id"]
            or str(checkpoint.run_id) != row["run_id"]
            or checkpoint.revision != row["revision"]
        ):
            raise StoredDataError("Checkpoint columns/payload mismatch")
        entries = []
        for item in connection.execute(
            "SELECT * FROM workflow_trace WHERE run_id=? ORDER BY sequence", (row["run_id"],)
        ):
            entry = ledger.decode(OrchestrationTraceEntry, item)
            if entry.content.sequence != item["sequence"] or entry.entry_id != item["entry_id"]:
                raise StoredDataError("Trace columns/payload mismatch")
            entries.append(entry)
        trace = OrchestrationTrace(incident_id=checkpoint.incident_id, entries=tuple(entries))
        if (
            not entries
            or entries[-1].content.result != checkpoint.result
            or entries[-1].content.snapshot != checkpoint.artifacts.snapshot
        ):
            raise StoredDataError("Checkpoint and trace head differ")
        return checkpoint, trace, row["claim"]

    def load(self, incident_id: UUID) -> tuple[WorkflowCheckpoint, OrchestrationTrace]:
        with self.database.transaction(write=False) as connection:
            checkpoint, trace, claim = self._read(connection, incident_id)
            if claim is not None:
                raise WorkflowInFlight("Step interrupted or active; automatic resume refused")
            return checkpoint, trace

    def _append(
        self, connection: Connection, run_id: UUID, entries: tuple[OrchestrationTraceEntry, ...]
    ) -> None:
        from soc_agent.review.identity import content_digest

        for entry in entries:
            cursor = connection.execute(
                "INSERT INTO workflow_trace VALUES (?,?,?,?,?)",
                (
                    str(run_id),
                    entry.content.sequence,
                    entry.entry_id,
                    ledger.serialize(entry),
                    content_digest(entry),
                ),
            )
            if cursor.rowcount != 1:
                raise StoredDataError("Trace insertion did not succeed")

    def create(self, checkpoint: WorkflowCheckpoint, trace: OrchestrationTrace) -> None:
        from soc_agent.review.identity import content_digest

        checkpoint = checked(WorkflowCheckpoint, checkpoint)
        trace = checked(OrchestrationTrace, trace)
        if checkpoint.revision != 0 or len(trace.entries) != 1:
            raise StoredDataError("New checkpoint must start at revision zero with one observation")
        with self.database.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO workflow_checkpoints VALUES (?,?,?,NULL,?,?)",
                (
                    str(checkpoint.incident_id),
                    str(checkpoint.run_id),
                    checkpoint.revision,
                    ledger.serialize(checkpoint),
                    content_digest(checkpoint),
                ),
            )
            if cursor.rowcount != 1:
                raise StoredDataError("Checkpoint insertion did not succeed")
            self._append(connection, checkpoint.run_id, trace.entries)
            self._read(connection, checkpoint.incident_id)

    def claim(self, expected: WorkflowCheckpoint) -> UUID:
        """Reserve this revision before any analysis or external call; no lease stealing."""
        with self.database.transaction() as connection:
            current, _, claim = self._read(connection, expected.incident_id)
            if current != expected:
                raise StaleCheckpoint("Checkpoint CAS conflict")
            if claim is not None:
                raise WorkflowInFlight("Another caller owns this workflow step")
            token = uuid4()
            cursor = connection.execute(
                "UPDATE workflow_checkpoints SET claim=? "
                "WHERE run_id=? AND revision=? AND claim IS NULL",
                (str(token), str(expected.run_id), expected.revision),
            )
            if cursor.rowcount != 1:
                raise StaleCheckpoint("Step claim conflict")
            return token

    def publish(
        self,
        expected: WorkflowCheckpoint,
        claim: UUID,
        updated: WorkflowCheckpoint,
        trace: OrchestrationTrace,
    ) -> None:
        from soc_agent.review.identity import content_digest

        updated = checked(WorkflowCheckpoint, updated)
        trace = checked(OrchestrationTrace, trace)
        with self.database.transaction() as connection:
            current, old_trace, token = self._read(connection, expected.incident_id)
            if current != expected or token != str(claim):
                raise StaleCheckpoint("Checkpoint publication CAS conflict")
            if (
                updated.run_id != expected.run_id
                or updated.incident_id != expected.incident_id
                or updated.revision != expected.revision + 1
                or updated.created_at != expected.created_at
                or updated.round_limit != expected.round_limit
                or updated.rounds < expected.rounds
                or not set(expected.attempted) <= set(updated.attempted)
                or trace.entries[: len(old_trace.entries)] != old_trace.entries
            ):
                raise StoredDataError("Invalid checkpoint/trace successor")
            self._append(connection, updated.run_id, trace.entries[len(old_trace.entries) :])
            cursor = connection.execute(
                "UPDATE workflow_checkpoints SET revision=?,claim=NULL,payload=?,digest=? "
                "WHERE run_id=? AND revision=? AND claim=?",
                (
                    updated.revision,
                    ledger.serialize(updated),
                    content_digest(updated),
                    str(expected.run_id),
                    expected.revision,
                    str(claim),
                ),
            )
            if cursor.rowcount != 1:
                raise StaleCheckpoint("Checkpoint update failed")
            self._read(connection, updated.incident_id)
