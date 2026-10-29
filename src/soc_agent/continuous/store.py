"""Service state and deduplication over existing private storage, audit and EventQueue."""

import json
import os
import tempfile
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
            c.execute(
                "CREATE TABLE continuous_segments(pin TEXT PRIMARY KEY,raw_pin TEXT,count INTEGER)"
            )
            c.execute(
                "CREATE TABLE continuous_native_cursor(cpu INTEGER PRIMARY KEY,generation TEXT,"
                "sequence TEXT,digest TEXT)"
            )
            c.execute(
                "CREATE TABLE continuous_native(id TEXT PRIMARY KEY,payload TEXT,digest TEXT)"
            )
            c.execute(
                "CREATE TABLE continuous_ingress(position INTEGER PRIMARY KEY,identity TEXT,"
                "payload TEXT,digest TEXT,applied INTEGER NOT NULL DEFAULT 0)"
            )
            c.execute(
                "CREATE TABLE continuous_auxiliary(id TEXT PRIMARY KEY,payload TEXT,digest TEXT)"
            )
            c.execute("CREATE TABLE continuous_checkpoint(payload TEXT,digest TEXT)")
            initial_cursor = {"position": 0, "identity": None}
            c.execute(
                "INSERT INTO continuous_checkpoint VALUES(?,?)",
                (json.dumps(initial_cursor), digest(initial_cursor)),
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
        # A committed display/health snapshot prevents GUI and external observers
        # from contending with ingestion writes. It is never admission authority.
        snapshot = dict(value)
        analysis = snapshot.get("analysis")
        if isinstance(analysis, dict) and isinstance(analysis.get("result"), dict):
            result = {k: v for k, v in analysis["result"].items() if k != "detail"}
            result["detail_reference"] = "OPEN_VERIFIED_ANALYSIS_OUTPUT_FOR_FULL_EVIDENCE"
            snapshot["analysis"] = analysis | dict(result=result)
        observation = dict(
            contract="soc-continuous-observation:v1",
            store_id=str(self.database.store_id),
            configuration=self.config.model_dump(mode="json"),
            snapshot=snapshot,
        )
        body = json.dumps(observation | dict(digest=digest(observation))).encode()
        if len(body) > 262144:
            raise ValueError("CONTINUOUS_OBSERVATION_BOUND")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=self.directory, prefix=".observation-", delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.directory / "observation.json")
            temporary = None
            descriptor = os.open(self.directory, os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

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
        if path.exists() or path.is_symlink():
            from soc_agent.security_ai.research.environment import read_local

            if digest(json.loads(read_local(path, 1024**2))) != pin:
                raise ValueError("CONTINUOUS_INPUT_CHANGED")
        else:
            write_new(path, job.model_dump(mode="json"))
        # The same immutable job can be handed off again after a process crash.
        # Return the existing queue admission rather than manufacture new arrival times.
        identity = uuid5(
            NAMESPACE_URL,
            content_digest(
                SourceIdentity(
                    namespace="scenario:network:continuous-job", generation="v1", record=pin
                )
            ),
        )
        with self.queue.database.transaction(write=False) as c:
            row = c.execute(
                "SELECT * FROM realtime_events WHERE event_id=?", (str(identity),)
            ).fetchone()
            if row:
                event = self.queue._decode(row)
                if dict(event.normalized_fields).get("job_digest") != pin:
                    raise ValueError("CONTINUOUS_JOB_IDENTITY_REUSE")
                return False
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

    def retain(self, raw):
        """Commit raw replay input before cursor publication or in-memory projection."""
        if self.config.source == "NATIVE_SERVICE":
            # Kernel records have independent generation/CPU identities. Never
            # treat an ordinary consumer restart as a repeated replay position.
            return
        body = json.dumps(raw)
        pin = digest(raw)
        position = raw["sequence"]
        if len(body.encode()) > 262144:
            raise ValueError("CONTINUOUS_INGRESS_BOUND")
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT digest FROM continuous_ingress WHERE position=?", (position,)
            ).fetchone()
            if row:
                if row["digest"] != pin:
                    raise ValueError("CONTINUOUS_REPLAY_POSITION_REUSED")
                return
            cursor = self._cursor(c)
            if position != cursor["position"] + 1:
                raise ValueError("CONTINUOUS_CHECKPOINT_SEQUENCE_GAP")
            if position > self.config.max_seen_events:
                raise ValueError("CONTINUOUS_INGRESS_RETENTION_QUOTA")
            c.execute(
                "INSERT INTO continuous_ingress(position,identity,payload,digest) VALUES(?,?,?,?)",
                (position, raw["id"], body, pin),
            )
            cursor = dict(position=position, identity=raw["id"])
            c.execute(
                "UPDATE continuous_checkpoint SET payload=?,digest=?",
                (json.dumps(cursor), digest(cursor)),
            )

    @staticmethod
    def _cursor(c):
        row = c.execute("SELECT * FROM continuous_checkpoint").fetchone()
        payload = json.loads(row["payload"])
        if digest(payload) != row["digest"]:
            raise ValueError("CONTINUOUS_CHECKPOINT_CORRUPT")
        return payload

    def retained(self):
        with self.database.transaction(write=False) as c:
            cursor = self._cursor(c)
            rows = c.execute("SELECT * FROM continuous_ingress ORDER BY position").fetchall()
            if len(rows) != cursor["position"]:
                raise ValueError("CONTINUOUS_INGRESS_MISSING_RECORD")
            result = []
            for i, row in enumerate(rows, 1):
                body = json.loads(row["payload"])
                if (
                    row["position"] != i
                    or body["sequence"] != i
                    or body["id"] != row["identity"]
                    or digest(body) != row["digest"]
                ):
                    raise ValueError("CONTINUOUS_INGRESS_CORRUPT")
                result.append(body)
            return result

    def applied(self, position):
        if self.config.source != "NATIVE_SERVICE":
            with self.database.transaction() as c:
                c.execute("UPDATE continuous_ingress SET applied=1 WHERE position=?", (position,))

    def native_event(self, raw, event):
        semantic = digest(raw)
        with self.database.transaction() as c:
            old = c.execute(
                "SELECT * FROM continuous_native_cursor WHERE cpu=?", (event.cpu,)
            ).fetchone()
            if old and old["generation"] == str(event.generation):
                if int(old["sequence"]) > event.cpu_sequence:
                    raise ValueError("CONTINUOUS_NATIVE_CURSOR_REGRESSION")
                if int(old["sequence"]) == event.cpu_sequence:
                    if old["digest"] != semantic:
                        raise ValueError("CONTINUOUS_NATIVE_EVENT_REUSE")
                    return False
            c.execute(
                "INSERT INTO continuous_native VALUES(?,?,?)",
                (raw["id"], json.dumps(raw), semantic),
            )
            c.execute(
                "INSERT INTO continuous_native_cursor VALUES(?,?,?,?) ON CONFLICT(cpu) DO "
                "UPDATE SET generation=excluded.generation,sequence=excluded.sequence,"
                "digest=excluded.digest",
                (event.cpu, str(event.generation), str(event.cpu_sequence), semantic),
            )
        with self.database.transaction(write=False) as c:
            count = c.execute("SELECT count(*) FROM continuous_native").fetchone()[0]
        if count >= min(4096, self.config.max_seen_events):
            self.compact_native()
        return True

    def compact_native(self):
        from soc_agent.continuous.segments import persist, read

        with self.database.transaction(write=False) as c:
            rows = c.execute("SELECT * FROM continuous_native ORDER BY rowid LIMIT 4096").fetchall()
        if not rows:
            return None
        records = []
        for row in rows:
            payload = json.loads(row["payload"])
            if digest(payload) != row["digest"]:
                raise ValueError("CONTINUOUS_NATIVE_STORED_INTEGRITY")
            records.append(payload)
        pin, raw_pin = persist(self.directory, records)
        if read(self.directory, pin, raw_pin) != records:
            raise ValueError("CONTINUOUS_SEGMENT_VERIFICATION")
        with self.database.transaction() as c:
            validate_audit(c)
            c.execute(
                "INSERT OR IGNORE INTO continuous_segments VALUES(?,?,?)", (pin, raw_pin, len(rows))
            )
            audit(c, "CONTINUOUS_NATIVE_SEGMENT_RETAINED", binding_digest=pin)
            # Segment verification + immutable index commit precedes active deletion.
            for row in rows:
                c.execute(
                    "DELETE FROM continuous_native WHERE id=? AND digest=?",
                    (row["id"], row["digest"]),
                )
        return pin

    def segments(self):
        from soc_agent.continuous.segments import read

        with self.database.transaction(write=False) as c:
            rows = c.execute("SELECT * FROM continuous_segments ORDER BY rowid").fetchall()
        return [
            dict(identity=r["pin"], records=len(read(self.directory, r["pin"], r["raw_pin"])))
            for r in rows
        ]

    def retain_auxiliary(self, identity, payload):
        with self.database.transaction() as c:
            row = c.execute(
                "SELECT digest FROM continuous_auxiliary WHERE id=?", (identity,)
            ).fetchone()
            if row:
                if row["digest"] != digest(payload):
                    raise ValueError("CONTINUOUS_AUXILIARY_REPLAY_CHANGED")
                return False
            if (
                c.execute("SELECT count(*) FROM continuous_auxiliary").fetchone()[0]
                >= self.config.max_seen_events
            ):
                raise ValueError("CONTINUOUS_AUXILIARY_QUOTA")
            c.execute(
                "INSERT INTO continuous_auxiliary VALUES(?,?,?)",
                (identity, json.dumps(payload), digest(payload)),
            )
        return True

    def auxiliary(self):
        with self.database.transaction(write=False) as c:
            rows = c.execute("SELECT * FROM continuous_auxiliary ORDER BY rowid").fetchall()
        result = []
        for row in rows:
            payload = json.loads(row["payload"])
            if digest(payload) != row["digest"]:
                raise ValueError("CONTINUOUS_AUXILIARY_CORRUPT")
            result.append(payload)
        return result

    def require_streaming_schema(self):
        with self.database.transaction(write=False) as c:
            names = {
                row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        if (
            not {
                "continuous_ingress",
                "continuous_checkpoint",
                "continuous_native_cursor",
                "continuous_segments",
                "continuous_auxiliary",
            }
            <= names
        ):
            raise ValueError("CONTINUOUS_STORAGE_V2_REQUIRES_NEW_DIRECTORY")
