"""Explicit SQLite authoritative store; no default path or automatic memory fallback."""

from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from soc_agent.review.identity import state_fingerprint
from soc_agent.review.models import ApplicationResult, StateAnchor, StoredIncident
from soc_agent.review.persistence import ledger
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.models import (
    AuthorizationStatus,
    GovernanceEvent,
    StoredDataError,
)
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.validation import checked
from soc_agent.state import Evidence, IncidentState


class SQLiteGovernanceStore:
    def __init__(self, path: Path, *, timeout: float = 5.0) -> None:
        self.database = GovernanceDatabase(path, timeout=timeout)

    @classmethod
    def create(cls, path: Path, *, timeout: float = 5.0) -> "SQLiteGovernanceStore":
        database = GovernanceDatabase.create(path, timeout=timeout)
        result = cls.__new__(cls)
        result.database = database
        return result

    @property
    def store_id(self) -> UUID:
        return self.database.store_id

    def register(self, state: IncidentState) -> StoredIncident:
        state = checked(IncidentState, state)
        anchor = StateAnchor(
            repository_id=self.store_id,
            incident_id=state.incident_id,
            revision=0,
            fingerprint=state_fingerprint(state),
        )
        payload = ledger.serialize(state)
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO incidents VALUES (?,?,?,?)",
                (str(state.incident_id), 0, anchor.fingerprint, payload),
            )
            connection.execute(
                "INSERT INTO snapshots VALUES (?,?,?,?)",
                (str(state.incident_id), 0, anchor.fingerprint, payload),
            )
            ledger.append_event(
                connection,
                GovernanceEvent(
                    event_type="incident_registered", incident_id=state.incident_id, after=anchor
                ),
            )
        return StoredIncident(state=state, anchor=anchor)

    def load(self, incident_id: UUID) -> StoredIncident:
        with self.database.transaction(write=False) as connection:
            return GovernanceSession(connection, self.store_id).load(incident_id)

    def compare_and_apply(
        self,
        expected: StateAnchor,
        authorization_id: UUID,
        build: Callable[[StoredIncident], ApplicationResult],
    ) -> ApplicationResult:
        with self.database.transaction() as connection:
            session = GovernanceSession(connection, self.store_id)
            session.restore_service()  # Check the persisted issuance/reference graph as well.
            return session.compare_and_apply(expected, authorization_id, build)

    def append_evidence(self, expected: StateAnchor, evidence: Evidence) -> StoredIncident:
        from soc_agent.review.errors import StaleSnapshotError

        expected = checked(StateAnchor, expected)
        evidence = checked(Evidence, evidence)
        with self.database.transaction() as connection:
            session = GovernanceSession(connection, self.store_id)
            current = session.load(expected.incident_id)
            if current.anchor != expected:
                raise StaleSnapshotError("Evidence ingestion CAS conflict")
            updated = current.state.add_evidence(evidence)
            anchor = session.save_state(expected, updated)
            ledger.append_event(
                connection,
                GovernanceEvent(
                    event_type="evidence_appended",
                    incident_id=expected.incident_id,
                    before=expected,
                    after=anchor,
                ),
            )
            return StoredIncident(state=updated, anchor=anchor)

    def authorization_status(self, authorization_id: UUID) -> AuthorizationStatus:
        """Fresh, idempotent reconciliation. Never applies or retries an operation."""
        with self.database.transaction(write=False) as connection:
            session = GovernanceSession(connection, self.store_id)
            session.restore_service()
            authorization = ledger.get(connection, "authorizations", str(authorization_id))
            application = session.application_for(authorization_id)
            return AuthorizationStatus(
                authorization=authorization,
                consumed=application is not None,
                application=application,
            )

    def applications(self) -> tuple[ApplicationResult, ...]:
        with self.database.transaction(write=False) as connection:
            session = GovernanceSession(connection, self.store_id)
            session.restore_service()
            results = ledger.all_records(connection, "applications")
            for result in results:
                if session.application_for(result.audit.authorization_id) != result:
                    raise StoredDataError("Application usage link mismatch")
            return results

    def events(self) -> tuple[GovernanceEvent, ...]:
        with self.database.transaction(write=False) as connection:
            events = []
            for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence"):
                event = ledger.decode(GovernanceEvent, row)
                if str(event.event_id) != row["event_id"] or event.event_type != row["event_type"]:
                    raise StoredDataError("Audit columns differ from validated event")
                events.append(event)
            return tuple(events)
