"""Service state and deduplication over existing private storage, audit and EventQueue."""

import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from soc_agent.continuous.models import ContinuousConfig
from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.external.runtime_store import DDL, audit, validate_audit
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import utc_now


class Store:
    def __init__(self, directory: Path):
        self.directory = directory
        self.database = GovernanceDatabase(directory / "service.sqlite")
        with self.database.transaction(write=False) as c:
            row = c.execute("SELECT payload,digest FROM continuous_config").fetchone()
            if row is None or digest(json.loads(row["payload"])) != row["digest"]:
                raise ValueError("CONTINUOUS_CONFIG_INTEGRITY")
            self.config = ContinuousConfig.model_validate_json(row["payload"])
        self.queue = EventQueue(
            directory / "queue.sqlite", capacity=self.config.queue_capacity, retry_limit=1
        )

    @classmethod
    def create(cls, directory, config):
        if directory.exists():
            raise ValueError("CONTINUOUS_NEW_DIRECTORY_REQUIRED")
        create_private_directory(directory, exist_ok=False)
        create_private_directory(directory / "inputs")
        create_private_directory(directory / "results")
        database = GovernanceDatabase.create(directory / "service.sqlite")
        EventQueue.create(directory / "queue.sqlite", capacity=config.queue_capacity, retry_limit=1)
        with database.transaction() as c:
            c.execute(DDL[-1])
            c.execute("CREATE TABLE continuous_config(payload TEXT,digest TEXT)")
            c.execute(
                "INSERT INTO continuous_config VALUES(?,?)",
                (config.model_dump_json(), digest(config.model_dump(mode="json"))),
            )
            c.execute(
                "CREATE TABLE continuous_state(payload TEXT,digest TEXT,stop INTEGER,reset INTEGER)"
            )
            initial = {"state": "STOPPED", "cleanup": "NOT_STARTED", "collection_live": False}
            c.execute(
                "INSERT INTO continuous_state VALUES(?,?,0,0)",
                (json.dumps(initial), digest(initial)),
            )
            c.execute("CREATE TABLE continuous_seen(id TEXT PRIMARY KEY,digest TEXT NOT NULL)")
            c.execute(
                "CREATE TABLE continuous_details(digest TEXT PRIMARY KEY,payload TEXT NOT NULL)"
            )
            audit(
                c, "CONTINUOUS_INITIALIZED", binding_digest=digest(config.model_dump(mode="json"))
            )
        return cls(directory)

    def event(self, code, details):
        with self.database.transaction() as c:
            validate_audit(c)
            pin = digest(details)
            c.execute(
                "INSERT OR IGNORE INTO continuous_details VALUES(?,?)", (pin, json.dumps(details))
            )
            audit(c, code, binding_digest=pin)

    def seen(self, identity, body):
        with self.database.transaction() as c:
            row = c.execute("SELECT digest FROM continuous_seen WHERE id=?", (identity,)).fetchone()
            if row:
                if row["digest"] != digest(body):
                    raise ValueError("CONTINUOUS_EVENT_IDENTITY_REUSE")
                return True
            if (
                c.execute("SELECT count(*) FROM continuous_seen").fetchone()[0]
                >= self.config.max_seen_events
            ):
                raise ValueError("CONTINUOUS_DEDUP_RETENTION_REQUIRES_ARCHIVAL")
            c.execute("INSERT INTO continuous_seen VALUES(?,?)", (identity, digest(body)))
        return False

    def update(self, value):
        with self.database.transaction() as c:
            c.execute(
                "UPDATE continuous_state SET payload=?,digest=?", (json.dumps(value), digest(value))
            )

    def state(self):
        with self.database.transaction(write=False) as c:
            validate_audit(c)
            for row in c.execute("SELECT digest,payload FROM continuous_details"):
                if digest(json.loads(row["payload"])) != row["digest"]:
                    raise ValueError("CONTINUOUS_AUDIT_DETAIL_CHANGED")
            row = c.execute("SELECT * FROM continuous_state").fetchone()
            value = json.loads(row["payload"])
            if digest(value) != row["digest"]:
                raise ValueError("CONTINUOUS_STATE_INTEGRITY")
            return value | dict(stop_requested=bool(row["stop"]), reset_worker=bool(row["reset"]))

    def control(self, *, stop=False, reset=False):
        with self.database.transaction() as c:
            c.execute("UPDATE continuous_state SET stop=?,reset=?", (int(stop), int(reset)))
            audit(c, "CONTINUOUS_STOP_REQUEST" if stop else "CONTINUOUS_OPERATOR_REQUEST")

    def enqueue(self, job):
        from soc_agent.security_ai.research.service import write_new

        pin = digest(job.model_dump(mode="json"))
        path = self.directory / "inputs" / (pin + ".json")
        if not path.exists():
            write_new(path, job.model_dump(mode="json"))
        source = SourceIdentity(
            namespace="scenario:network:continuous-job", generation="v1", record=pin
        )
        event = CommonEvent(
            schema_version="soc-common-event:v2",
            platform="validated_fixture",
            collector_id="scenario-network-capture:v1",
            event_type="os_record",
            event_id=uuid5(NAMESPACE_URL, content_digest(source)),
            event_timestamp=utc_now(),
            ingestion_timestamp=utc_now(),
            source=source,
            metadata=SourceMetadata(
                channel="CONTINUOUS_REPLAY", provider="soc-continuous:v1", code=job.kind
            ),
            normalized_fields=(("job_digest", pin),),
            provenance="explicit_log_fixture",
        )
        return self.queue.enqueue(event)

    def input_path(self, event):
        pin = dict(event.normalized_fields)["job_digest"]
        import re

        if not re.fullmatch("[a-f0-9]{64}", pin):
            raise ValueError("CONTINUOUS_JOB_REFERENCE")
        return self.directory / "inputs" / (pin + ".json")
