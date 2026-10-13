"""Private isolated SQLite queue. Enqueue and cursor publication share one transaction."""

import json
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from soc_agent.realtime.models import CommonEvent
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.external.models import content_digest_payload


class QueueFull(ValueError):
    pass


class QueueIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class Claim:
    event: CommonEvent
    token: str
    attempts: int


class EventQueue:
    """Single writer service; recover requires exclusive service lock, not a lease guess."""

    def __init__(self, path: Path, *, capacity: int = 256, retry_limit: int = 3):
        if not 1 <= capacity <= 10000 or not 1 <= retry_limit <= 10:
            raise ValueError("Queue limits invalid")
        self.database = GovernanceDatabase(path)
        with self.database.transaction(write=False) as c:
            row = c.execute("SELECT version,capacity,retries FROM realtime_queue_config").fetchall()
            if [tuple(r) for r in row] != [(1, capacity, retry_limit)]:
                raise QueueIntegrityError("Queue configuration mismatch")
        self.capacity, self.retry_limit = capacity, retry_limit

    @classmethod
    def create(cls, path: Path, *, capacity=256, retry_limit=3):
        if not 1 <= capacity <= 10000 or not 1 <= retry_limit <= 10:
            raise ValueError("Queue limits invalid")
        create_private_directory(path.parent)
        db = GovernanceDatabase.create(path)
        with db.transaction() as c:
            c.execute(
                "CREATE TABLE realtime_queue_config(version INTEGER,capacity "
                "INTEGER,retries INTEGER)"
            )
            c.execute("INSERT INTO realtime_queue_config VALUES(1,?,?)", (capacity, retry_limit))
            c.execute("""CREATE TABLE realtime_events(
                event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING','CLAIMED','DONE','POISON')),
                attempts INTEGER NOT NULL, token TEXT, outcome TEXT)""")
            c.execute("CREATE INDEX realtime_pending ON realtime_events(status)")
            c.execute(
                "CREATE TABLE realtime_cursors(source TEXT PRIMARY KEY,event_id "
                "TEXT NOT NULL REFERENCES realtime_events(event_id),digest TEXT NOT NULL)"
            )
        return cls(path, capacity=capacity, retry_limit=retry_limit)

    @staticmethod
    def _decode(row):
        try:
            if len(row["payload"].encode("utf-8")) > 262144:
                raise ValueError
            event = CommonEvent.model_validate_json(row["payload"])
            if str(event.event_id) != row["event_id"] or event.source_digest != row["digest"]:
                raise ValueError
            return event
        except (ValueError, TypeError) as error:
            raise QueueIntegrityError("Stored event integrity rejected") from error

    def enqueue(self, event: CommonEvent, *, cursor_source: str | None = None) -> bool:
        event = CommonEvent.model_validate(event.model_dump())
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT * FROM realtime_events WHERE event_id=?", (str(event.event_id),)
            ).fetchone()
            if row:
                if self._decode(row).source_digest != event.source_digest:
                    raise QueueIntegrityError(
                        "Source record identity reused with different content"
                    )
            else:
                if (
                    c.execute(
                        "SELECT count(*) FROM realtime_events WHERE status IN ('PENDING','CLAIMED')"
                    ).fetchone()[0]
                    >= self.capacity
                ):
                    raise QueueFull("Backpressure: cursor not advanced")
                # Bounded tombstone retention, fail rather than discard dedup history.
                if c.execute("SELECT count(*) FROM realtime_events").fetchone()[0] >= 100000:
                    raise QueueFull("Retention capacity reached; operator archival required")
                c.execute(
                    "INSERT INTO realtime_events VALUES(?,?,?,'PENDING',0,NULL,NULL)",
                    (str(event.event_id), event.model_dump_json(), event.source_digest),
                )
            if cursor_source:
                cursor_digest = content_digest_payload(
                    {
                        "source": cursor_source,
                        "event_id": str(event.event_id),
                        "event_digest": event.source_digest,
                    }
                )
                c.execute(
                    "INSERT INTO realtime_cursors VALUES(?,?,?) ON CONFLICT(source) DO "
                    "UPDATE SET event_id=excluded.event_id,digest=excluded.digest",
                    (cursor_source, str(event.event_id), cursor_digest),
                )
            return row is None

    def cursor(self, source: str) -> CommonEvent | None:
        with self.database.transaction(write=False) as c:
            row = c.execute(
                "SELECT e.*, x.digest AS cursor_digest FROM realtime_cursors x "
                "LEFT JOIN realtime_events e "
                "USING(event_id) WHERE x.source=?",
                (source,),
            ).fetchone()
            if row is None:
                return None
            event = self._decode(row)
            expected = content_digest_payload(
                {
                    "source": source,
                    "event_id": str(event.event_id),
                    "event_digest": event.source_digest,
                }
            )
            if row["cursor_digest"] != expected:
                raise QueueIntegrityError("Collector cursor integrity rejected")
            return event

    def recover(self):
        """Caller must hold writer_lock for the entire collector/worker lifetime."""
        with self.database.transaction() as c:
            c.execute(
                "UPDATE realtime_events SET status=CASE WHEN attempts>=? THEN "
                "'POISON' ELSE 'PENDING' END, token=NULL WHERE status='CLAIMED'",
                (self.retry_limit,),
            )

    def claim(self) -> Claim | None:
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT * FROM realtime_events WHERE status='PENDING' ORDER BY rowid LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            event = self._decode(row)
            token = str(uuid4())
            c.execute(
                "UPDATE realtime_events SET "
                "status='CLAIMED',attempts=attempts+1,token=? WHERE event_id=?",
                (token, str(event.event_id)),
            )
            return Claim(event, token, row["attempts"] + 1)

    def finish(self, claim: Claim, outcome: dict[str, object]):
        # Persist only sanitized outcome fields from the trusted worker.
        if set(outcome) - {"inference", "incident_id", "workflow", "human_boundary"}:
            raise ValueError("Unexpected queue outcome fields")
        with self.database.transaction() as c:
            changed = c.execute(
                "UPDATE realtime_events SET status='DONE',token=NULL,outcome=? "
                "WHERE event_id=? AND status='CLAIMED' AND token=?",
                (json.dumps(outcome, allow_nan=False), str(claim.event.event_id), claim.token),
            ).rowcount
            if changed != 1:
                raise QueueIntegrityError("Stale worker acknowledgement")

    def fail(self, claim: Claim, category: str = "WORKER_FAILURE"):
        if category not in {
            "WORKER_FAILURE",
            "INFERENCE_UNAVAILABLE",
            "INVALID_INPUT",
            "STORAGE_FAILURE",
        }:
            raise ValueError("Unknown failure category")
        with self.database.transaction() as c:
            status = "POISON" if claim.attempts >= self.retry_limit else "PENDING"
            if (
                c.execute(
                    "UPDATE realtime_events SET status=?,token=NULL,outcome=? WHERE event_id=? "
                    "AND status='CLAIMED' AND token=?",
                    (
                        status,
                        json.dumps({"failure_category": category}),
                        str(claim.event.event_id),
                        claim.token,
                    ),
                ).rowcount
                != 1
            ):
                raise QueueIntegrityError("Stale worker failure")

    def counts(self):
        with self.database.transaction(write=False) as c:
            return dict(
                c.execute("SELECT status,count(*) FROM realtime_events GROUP BY status").fetchall()
            )
