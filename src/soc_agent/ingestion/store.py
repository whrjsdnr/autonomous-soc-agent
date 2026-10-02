"""Opt-in, versioned ingestion extension on the existing governance transaction layer."""

from uuid import NAMESPACE_URL, UUID, uuid5

from soc_agent.ingestion.models import IngestionReceipt, IngestionResult, SOCEvent
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import StoredDataError, UnsupportedSchemaError
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.review.validation import checked
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now


class EventConflict(ValueError):
    pass


def migrate_ingestion(store: SQLiteGovernanceStore) -> None:
    """Independent optional extension v1. Governance schema v4 is not reset/relabelled."""
    with store.database.transaction() as connection:
        if connection.execute("PRAGMA user_version").fetchone()[0] not in (4, 5, 6, 7):
            raise UnsupportedSchemaError("Ingestion requires checkpoint schema v4")
        exists = connection.execute(
            "SELECT name FROM sqlite_master WHERE name='soc_ingestion_schema'"
        ).fetchone()
        if exists:
            versions = connection.execute("SELECT version FROM soc_ingestion_schema").fetchall()
            if len(versions) != 1 or versions[0][0] != 1:
                raise UnsupportedSchemaError("Unsupported ingestion extension version")
            connection.execute(
                "SELECT event_id, incident_id, payload, digest FROM soc_events LIMIT 0"
            )
            return
        if connection.execute("SELECT name FROM sqlite_master WHERE name='soc_events'").fetchone():
            raise StoredDataError("Unversioned event table; no silent adoption")
        connection.execute("CREATE TABLE soc_ingestion_schema (version INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO soc_ingestion_schema VALUES (1)")
        connection.execute("""CREATE TABLE soc_events (
            event_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL UNIQUE REFERENCES incidents,
            payload TEXT NOT NULL, digest TEXT NOT NULL)""")


class EventIngestor:
    def __init__(self, store: SQLiteGovernanceStore) -> None:
        self.store = store
        # Explicit migration is a composition responsibility.
        with store.database.transaction(write=False) as connection:
            rows = connection.execute("SELECT version FROM soc_ingestion_schema").fetchall()
            if len(rows) != 1 or rows[0][0] != 1:
                raise UnsupportedSchemaError("Unsupported ingestion extension")

    @staticmethod
    def _decode(row) -> IngestionReceipt:
        receipt = ledger.decode(IngestionReceipt, row)
        if (
            str(receipt.event.event_id) != row["event_id"]
            or str(receipt.incident_id) != row["incident_id"]
            or content_digest(receipt.event) != receipt.canonical_digest
        ):
            raise StoredDataError("Event provenance mismatch")
        return receipt

    def load(self, incident_id: UUID) -> IngestionReceipt:
        with self.store.database.transaction(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM soc_events WHERE incident_id=?", (str(incident_id),)
            ).fetchone()
            if row is None:
                raise ValueError("No event for incident")
            receipt = self._decode(row)
            GovernanceSession(connection, self.store.store_id).load(receipt.incident_id)
            return receipt

    def ingest(self, event: SOCEvent) -> IngestionResult:
        event = checked(SOCEvent, event)
        digest = content_digest(event)
        with self.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM soc_events WHERE event_id=?", (str(event.event_id),)
            ).fetchone()
            if row:
                receipt = self._decode(row)
                if receipt.event != event:
                    raise EventConflict("Event identity has conflicting content")
                GovernanceSession(connection, self.store.store_id).load(receipt.incident_id)
            else:
                incident_id = uuid5(
                    NAMESPACE_URL, f"soc-agent:authentication-event:{event.event_id}"
                )
                state = IncidentState(incident_id=incident_id)
                GovernanceSession(connection, self.store.store_id).register(state)
                receipt = IngestionReceipt(
                    event=event,
                    incident_id=incident_id,
                    canonical_digest=digest,
                    received_at=utc_now(),
                )
                connection.execute(
                    "INSERT INTO soc_events VALUES (?,?,?,?)",
                    (
                        str(event.event_id),
                        str(incident_id),
                        ledger.serialize(receipt),
                        content_digest(receipt),
                    ),
                )
            return IngestionResult(
                incident_id=receipt.incident_id,
                event_id=event.event_id,
                canonical_digest=digest,
                ingestion_version=receipt.ingestion_version,
                duplicate=bool(row),
            )
