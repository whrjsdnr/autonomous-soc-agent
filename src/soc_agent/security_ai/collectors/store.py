"""Reuse RuntimeStore transactions/hash audit; persist only normalized diagnostics."""

import json
from pathlib import Path

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.collectors.models import CollectedEvent, Event, Source
from soc_agent.security_ai.research.models import digest


class CollectorStore:
    def __init__(self, directory: Path, source: Source | None = None):
        from soc_agent.review.persistence.secure_storage import create_private_directory

        directory = directory.absolute()
        create_private_directory(directory)
        self.directory = directory
        self.runtime = (
            RuntimeStore.create(
                directory,
                RuntimeConfig(
                    incident_id=source.session_id,
                    repeated_failures=5,
                    multiple_accounts=3,
                    assessment_mode="READ_ONLY",
                ),
            )
            if source
            else RuntimeStore(directory)
        )
        if source:
            with self.runtime.database.transaction() as c:
                c.execute(
                    "CREATE TABLE collector_identity(value TEXT NOT NULL,digest TEXT NOT NULL)"
                )
                c.execute(
                    "INSERT INTO collector_identity VALUES(?,?)",
                    (source.model_dump_json(), digest(source.model_dump(mode="json"))),
                )
                c.execute(
                    "CREATE TABLE collector_events(sequence INTEGER PRIMARY KEY,id TEXT UNIQUE,"
                    "payload TEXT,digest TEXT)"
                )
                c.execute(
                    "CREATE TABLE collector_cursors(kind TEXT PRIMARY KEY,value TEXT,digest TEXT)"
                )
                self.runtime._audit(
                    c, "COLLECTOR_PREPARED", dict(source=source.model_dump(mode="json"))
                )
        self.verify()

    def verify(self):
        self.runtime.verify_audit()
        with self.runtime.database.transaction(write=False) as c:
            row = c.execute("SELECT value,digest FROM collector_identity").fetchone()
            self.source = Source.model_validate_json(row[0])
            if digest(self.source.model_dump(mode="json")) != row[1]:
                raise ValueError("ZEEK_SOURCE_IDENTITY_CORRUPT")
            expected_events, expected_cursors = {}, {}
            identities = []
            for raw in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence"):
                audit = json.loads(raw[0])
                if audit["kind"] == "COLLECTOR_PREPARED":
                    identities.append(audit["details"]["source"])
                if audit["kind"] == "COLLECTOR_BATCH_COMMITTED":
                    details = audit["details"]
                    expected_events.update(details["event_digests"])
                    expected_cursors[details["kind"]] = details["cursor_digest"]
            if identities != [self.source.model_dump(mode="json")]:
                raise ValueError("ZEEK_SOURCE_AUDIT_BINDING_FAILED")
            rows = c.execute(
                "SELECT sequence,payload,digest,id FROM collector_events ORDER BY sequence"
            ).fetchall()
            if len(rows) != len(expected_events):
                raise ValueError("ZEEK_EVENT_AUDIT_BINDING_FAILED")
            if len(rows) > 4096:
                raise ValueError("ZEEK_EVENT_STORAGE_LIMIT")
            for n, row in enumerate(rows, 1):
                event = Event.model_validate_json(row[1])
                if (
                    row[0] != n
                    or row[3] != event.event_id
                    or expected_events.get(event.event_id) != row[2]
                    or event.source != self.source
                    or digest(event.model_dump(mode="json")) != row[2]
                ):
                    raise ValueError("ZEEK_EVENT_INTEGRITY_FAILED")
            cursors = c.execute("SELECT value,digest,kind FROM collector_cursors").fetchall()
            if {row[2] for row in cursors} != set(expected_cursors):
                raise ValueError("ZEEK_CURSOR_AUDIT_BINDING_FAILED")
            for row in cursors:
                if digest(json.loads(row[0])) != row[1] or expected_cursors.get(row[2]) != row[1]:
                    raise ValueError("ZEEK_CURSOR_INTEGRITY_FAILED")

    def cursor(self, kind):
        with self.runtime.database.transaction(write=False) as c:
            row = c.execute(
                "SELECT value,digest FROM collector_cursors WHERE kind=?", (kind,)
            ).fetchone()
            if row is None:
                return None
            value = json.loads(row[0])
            if digest(value) != row[1]:
                raise ValueError("ZEEK_CURSOR_INTEGRITY_FAILED")
            return value

    def commit(self, kind: str, events: list[Event], cursor: dict):
        with self.runtime.database.transaction() as c:
            count = c.execute("SELECT count(*) FROM collector_events").fetchone()[0]
            inserted = duplicates = 0
            event_digests = {}
            for e in events:
                if e.source != self.source or e.kind != kind:
                    raise ValueError("ZEEK_SOURCE_FORGERY")
                content = e.model_dump(mode="json")
                sha = digest(content)
                event_digests[e.event_id] = sha
                old = c.execute(
                    "SELECT digest FROM collector_events WHERE id=?", (e.event_id,)
                ).fetchone()
                if old:
                    if old[0] != sha:
                        raise ValueError("ZEEK_DUPLICATE_ID_CONFLICT")
                    duplicates += 1
                    continue
                if count + inserted >= 4096:
                    raise ValueError("ZEEK_EVENT_STORAGE_LIMIT")
                inserted += 1
                c.execute(
                    "INSERT INTO collector_events VALUES(?,?,?,?)",
                    (count + inserted, e.event_id, e.model_dump_json(), sha),
                )
            value = json.dumps(cursor)
            c.execute(
                "INSERT OR REPLACE INTO collector_cursors VALUES(?,?,?)",
                (kind, value, digest(cursor)),
            )
            self.runtime._audit(
                c,
                "COLLECTOR_BATCH_COMMITTED",
                dict(
                    kind=kind,
                    inserted=inserted,
                    duplicates=duplicates,
                    cursor_digest=digest(cursor),
                    event_digests=event_digests,
                ),
            )
        return inserted, duplicates

    def events(self, kind=None):
        with self.runtime.database.transaction(write=False) as c:
            if kind is None:
                rows = c.execute(
                    "SELECT payload,sequence FROM collector_events ORDER BY sequence DESC LIMIT 128"
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT payload,sequence FROM collector_events "
                    "WHERE json_extract(payload,'$.kind')=? "
                    "ORDER BY sequence DESC LIMIT 128",
                    (kind,),
                ).fetchall()
            return [
                CollectedEvent(collector_sequence=r[1], **json.loads(r[0])).model_dump(mode="json")
                for r in reversed(rows)
            ]

    def counts(self):
        with self.runtime.database.transaction(write=False) as c:
            return dict(
                c.execute(
                    "SELECT json_extract(payload,'$.kind'),count(*) "
                    "FROM collector_events GROUP BY 1"
                ).fetchall()
            )
