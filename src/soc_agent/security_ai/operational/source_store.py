"""Isolated secure SQLite operational intake, not the governed Incident database."""

from datetime import datetime, timedelta
from pathlib import Path
from sqlite3 import Connection, Row
from typing import Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import JsonValue, TypeAdapter

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.authentication.aggregation import (
    AuthenticationWindow,
    AuthenticationWindowExtractor,
)
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.features.models import SecurityRecord, SourceReference, SourceType
from soc_agent.security_ai.operational.source_records import AuthenticationSource, OperationalSource
from soc_agent.state.evidence import UTCTimestamp


class SourceRejected(ValueError):
    pass


class SourceAdmission(Snapshot):
    source_digest: Hash
    status: Literal["ACCEPTED", "LATE_QUARANTINED"]
    duplicate: bool


class AuthenticationSnapshot(Snapshot):
    contract_version: Literal["soc-operational-auth-window:v1"] = "soc-operational-auth-window:v1"
    incident_id: UUID
    window: AuthenticationWindow
    source_digests: tuple[Hash, ...]
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    source_assurance: Literal["DECLARED_UNATTESTED"] = "DECLARED_UNATTESTED"


class OperationalSourceStore:
    def __init__(
        self,
        path: Path,
        *,
        allowed_lateness_seconds: int,
        max_future_skew_seconds: int,
        capacity: int = 4096,
    ) -> None:
        self.database = GovernanceDatabase(path)
        self._config(allowed_lateness_seconds, max_future_skew_seconds, capacity)
        with self.database.transaction(write=False) as c:
            rows = c.execute(
                "SELECT version,lateness,skew,capacity FROM operational_source_config"
            ).fetchall()
            if [tuple(r) for r in rows] != [
                (1, allowed_lateness_seconds, max_future_skew_seconds, capacity)
            ]:
                raise SourceRejected("SOURCE_STORE_CONFIG_MISMATCH")

    @staticmethod
    def _validate_limits(lateness: int, skew: int, capacity: int) -> None:
        if (
            any(type(x) is not int for x in (lateness, skew, capacity))
            or not 0 <= lateness <= 3600
            or not 0 <= skew <= 300
            or not 1 <= capacity <= 10000
        ):
            raise SourceRejected("INVALID_SOURCE_LIMITS")

    def _config(self, lateness: int, skew: int, capacity: int) -> None:
        self._validate_limits(lateness, skew, capacity)
        self.lateness, self.skew, self.capacity = lateness, skew, capacity

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        allowed_lateness_seconds: int,
        max_future_skew_seconds: int,
        capacity: int = 4096,
    ) -> Self:
        cls._validate_limits(allowed_lateness_seconds, max_future_skew_seconds, capacity)
        if path.exists():
            raise SourceRejected("EXISTING_DATABASE_NOT_ADOPTED")
        create_private_directory(path.parent)
        db = GovernanceDatabase.create(path)
        with db.transaction() as c:
            c.execute(
                "CREATE TABLE operational_source_config(version INTEGER,lateness "
                "INTEGER,skew INTEGER,capacity INTEGER)"
            )
            c.execute(
                "INSERT INTO operational_source_config VALUES(1,?,?,?)",
                (allowed_lateness_seconds, max_future_skew_seconds, capacity),
            )
            c.execute("""CREATE TABLE operational_sources(
                source_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                event_key TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,digest TEXT NOT NULL,status TEXT NOT NULL,
                arrival TEXT NOT NULL,row_digest TEXT NOT NULL)""")
            c.execute(
                "CREATE INDEX operational_incident ON operational_sources(incident_id,status)"
            )
            c.execute(
                "CREATE TABLE operational_watermarks(incident_id TEXT PRIMARY KEY, "
                "maximum TEXT NOT NULL,digest TEXT NOT NULL)"
            )
            c.execute(
                "CREATE TABLE operational_auth_windows(window_key TEXT PRIMARY "
                "KEY,incident_id TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL)"
            )
        return cls(
            path,
            allowed_lateness_seconds=allowed_lateness_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
            capacity=capacity,
        )

    @staticmethod
    def _row_digest(
        key: str, incident: str, event: str, payload: str, digest: str, status: str, arrival: str
    ) -> str:
        return content_digest_payload(
            dict(
                zip(
                    (
                        "source_key",
                        "incident_id",
                        "event_key",
                        "payload",
                        "digest",
                        "status",
                        "arrival",
                    ),
                    (key, incident, event, payload, digest, status, arrival),
                    strict=True,
                )
            )
        )

    @classmethod
    def _decode(cls, row: Row) -> OperationalSource:
        try:
            source = TypeAdapter(OperationalSource).validate_json(row["payload"])
            key = content_digest_payload(source.header.source.model_dump(mode="json"))
            event = content_digest_payload(
                {
                    "namespace": source.header.source.namespace,
                    "generation": source.header.source.generation,
                    "event_id": source.header.event_id,
                }
            )
            fields = tuple(
                row[name]
                for name in (
                    "source_key",
                    "incident_id",
                    "event_key",
                    "payload",
                    "digest",
                    "status",
                    "arrival",
                )
            )
            if (
                key != row["source_key"]
                or event != row["event_key"]
                or str(source.header.incident_id) != row["incident_id"]
                or source.content_digest != row["digest"]
                or cls._row_digest(*fields) != row["row_digest"]
                or row["status"] not in ("ACCEPTED", "LATE_QUARANTINED")
            ):
                raise ValueError
            return source
        except (ValueError, TypeError) as error:
            raise SourceRejected("STORED_SOURCE_INTEGRITY_REJECTED") from error

    def _maximum(self, c: Connection, incident: UUID) -> datetime | None:
        row = c.execute(
            "SELECT * FROM operational_watermarks WHERE incident_id=?", (str(incident),)
        ).fetchone()
        if row is None:
            return None
        if row["digest"] != content_digest_payload(
            {"incident_id": str(incident), "maximum": row["maximum"]}
        ):
            raise SourceRejected("WATERMARK_INTEGRITY_REJECTED")
        try:
            return TypeAdapter(UTCTimestamp).validate_python(row["maximum"])
        except ValueError as error:
            raise SourceRejected("WATERMARK_TIME_REJECTED") from error

    def ingest(
        self,
        source: OperationalSource,
        *,
        expected_incident: UUID,
        expected_source_digest: str,
        received_at: datetime,
    ) -> SourceAdmission:
        source = TypeAdapter(OperationalSource).validate_python(source.model_dump())
        received = TypeAdapter(UTCTimestamp).validate_python(received_at)
        if source.header.incident_id != expected_incident:
            raise SourceRejected("INCIDENT_MISMATCH")
        if source.content_digest != expected_source_digest:
            raise SourceRejected("SOURCE_DIGEST_MISMATCH")
        if source.header.observed_at > received + timedelta(seconds=self.skew):
            raise SourceRejected("SOURCE_TIME_IN_FUTURE")
        key = content_digest_payload(source.header.source.model_dump(mode="json"))
        event = content_digest_payload(
            {
                "namespace": source.header.source.namespace,
                "generation": source.header.source.generation,
                "event_id": source.header.event_id,
            }
        )
        with self.database.transaction() as c:
            self._windows(c, expected_incident)
            existing = c.execute(
                "SELECT * FROM operational_sources WHERE source_key=? OR event_key=?", (key, event)
            ).fetchall()
            if existing:
                if len(existing) != 1 or self._decode(existing[0]) != source:
                    raise SourceRejected("SOURCE_IDENTITY_CONFLICT")
                return SourceAdmission(
                    source_digest=source.content_digest,
                    status=existing[0]["status"],
                    duplicate=True,
                )
            if c.execute("SELECT count(*) FROM operational_sources").fetchone()[0] >= self.capacity:
                raise SourceRejected("SOURCE_CAPACITY_REACHED")
            maximum = (
                self._maximum(c, expected_incident)
                if isinstance(source, AuthenticationSource)
                else None
            )
            status = (
                "LATE_QUARANTINED"
                if maximum is not None
                and source.header.observed_at < maximum - timedelta(seconds=self.lateness)
                else "ACCEPTED"
            )
            values = (
                key,
                str(expected_incident),
                event,
                source.model_dump_json(),
                source.content_digest,
                status,
                received.isoformat(),
            )
            c.execute(
                "INSERT INTO operational_sources VALUES(?,?,?,?,?,?,?,?)",
                (*values, self._row_digest(*values)),
            )
            if status == "ACCEPTED" and isinstance(source, AuthenticationSource):
                maximum = max(maximum or source.header.observed_at, source.header.observed_at)
                value = maximum.isoformat()
                digest = content_digest_payload(
                    {"incident_id": str(expected_incident), "maximum": value}
                )
                c.execute(
                    "INSERT INTO operational_watermarks VALUES(?,?,?) ON "
                    "CONFLICT(incident_id) DO UPDATE SET "
                    "maximum=excluded.maximum,digest=excluded.digest",
                    (str(expected_incident), value, digest),
                )
                if isinstance(source, AuthenticationSource):
                    self._snapshot(c, source)
            return SourceAdmission(
                source_digest=source.content_digest, status=status, duplicate=False
            )

    @staticmethod
    def _window_key(snapshot: AuthenticationSnapshot) -> str:
        return content_digest_payload(
            {
                "incident": str(snapshot.incident_id),
                "account": snapshot.window.account_id,
                "start": snapshot.window.started_at.isoformat(),
            }
        )

    @staticmethod
    def _stable_window(snapshot: AuthenticationSnapshot) -> dict[str, JsonValue]:
        # Factory timestamps are not feature semantics; stored timestamps remain intact.
        return snapshot.model_dump(mode="json", exclude={"window": {"features": {"created_at"}}})

    def _derive(self, c: Connection, incident_id: UUID) -> tuple[AuthenticationSnapshot, ...]:
        rows = c.execute(
            "SELECT * FROM operational_sources WHERE incident_id=? AND "
            "status='ACCEPTED' ORDER BY source_key",
            (str(incident_id),),
        ).fetchall()
        records = []
        digests = []
        for row in rows:
            item = self._decode(row)
            if not isinstance(item, AuthenticationSource):
                continue
            # Existing extractor owns UTC half-open 300s window/count/rate calculations.
            records.append(
                SecurityRecord(
                    record_id=uuid5(NAMESPACE_URL, row["source_key"]),
                    incident_id=None,
                    record_type="authentication_event",
                    record_schema_version="1.0.0",
                    source=item.header.collector_id,
                    source_reference=SourceReference(
                        source_type=SourceType.STREAM,
                        source_name=item.header.source.namespace,
                        source_version="1.0.0",
                        record_id=row["source_key"],
                    ),
                    fields=item.event.model_dump(mode="json"),
                    observed_at=item.header.observed_at,
                )
            )
            digests.append((item.event.event_id, item.content_digest))
        result = []
        for window in AuthenticationWindowExtractor().extract(tuple(records)):
            refs = tuple(dict(digests)[eid] for eid in window.event_ids)
            fingerprint = content_digest_payload(
                {
                    "incident": str(incident_id),
                    "account": window.account_id,
                    "start": window.started_at.isoformat(),
                    "sources": list(refs),
                }
            )
            features = window.features.model_copy(
                update={
                    "feature_set_id": uuid5(NAMESPACE_URL, fingerprint),
                }
            )
            window = AuthenticationWindow.model_validate(
                window.model_dump() | {"features": features.model_dump()}
            )
            snapshot = AuthenticationSnapshot(
                incident_id=incident_id, window=window, source_digests=refs
            )
            result.append(snapshot)
        return tuple(result)

    def _snapshot(self, c: Connection, source: AuthenticationSource) -> None:
        for snapshot in self._derive(c, source.header.incident_id):
            key = self._window_key(snapshot)
            existing = c.execute(
                "SELECT payload FROM operational_auth_windows WHERE window_key=?", (key,)
            ).fetchone()
            if existing:
                previous = AuthenticationSnapshot.model_validate_json(existing["payload"])
                if self._stable_window(previous) == self._stable_window(snapshot):
                    continue
            payload = snapshot.model_dump_json()
            digest = content_digest_payload(snapshot.model_dump(mode="json"))
            c.execute(
                "INSERT INTO operational_auth_windows VALUES(?,?,?,?) ON "
                "CONFLICT(window_key) DO UPDATE SET "
                "payload=excluded.payload,digest=excluded.digest",
                (key, str(source.header.incident_id), payload, digest),
            )

    def windows(self, incident_id: UUID) -> tuple[AuthenticationSnapshot, ...]:
        with self.database.transaction(write=False) as c:
            return self._windows(c, incident_id)

    def _windows(self, c: Connection, incident_id: UUID) -> tuple[AuthenticationSnapshot, ...]:
        maximum = self._maximum(c, incident_id)
        source_rows = c.execute(
            "SELECT * FROM operational_sources WHERE incident_id=?", (str(incident_id),)
        ).fetchall()
        known = {}
        for row in source_rows:
            item = self._decode(row)
            known[item.content_digest] = (item, row["status"])
        accepted_times = [
            item.header.observed_at
            for item, status in known.values()
            if isinstance(item, AuthenticationSource) and status == "ACCEPTED"
        ]
        if maximum != max(accepted_times, default=None):
            raise SourceRejected("WATERMARK_SOURCE_MISMATCH")
        expected = {self._window_key(s): s for s in self._derive(c, incident_id)}
        result = []
        for row in c.execute(
            "SELECT * FROM operational_auth_windows WHERE incident_id=? ORDER BY window_key",
            (str(incident_id),),
        ):
            try:
                snap = AuthenticationSnapshot.model_validate_json(row["payload"])
            except ValueError as error:
                raise SourceRejected("WINDOW_SOURCE_INTEGRITY_REJECTED") from error
            if (
                row["window_key"] not in expected
                or self._window_key(snap) != row["window_key"]
                or self._stable_window(snap) != self._stable_window(expected[row["window_key"]])
                or snap.incident_id != incident_id
                or content_digest_payload(snap.model_dump(mode="json")) != row["digest"]
                or any(d not in known or known[d][1] != "ACCEPTED" for d in snap.source_digests)
            ):
                raise SourceRejected("WINDOW_SOURCE_INTEGRITY_REJECTED")
            result.append(snap)
        if len(result) != len(expected):
            raise SourceRejected("WINDOW_COVERAGE_MISMATCH")
        return tuple(result)

    def load(self, source: OperationalSource, *, expected_incident: UUID) -> OperationalSource:
        key = content_digest_payload(source.header.source.model_dump(mode="json"))
        with self.database.transaction(write=False) as c:
            row = c.execute(
                "SELECT * FROM operational_sources WHERE source_key=?", (key,)
            ).fetchone()
            if row is None:
                raise SourceRejected("SOURCE_UNAVAILABLE")
            stored = self._decode(row)
            if (
                stored.header.incident_id != expected_incident
                or stored.content_digest != source.content_digest
            ):
                raise SourceRejected("SOURCE_ASSOCIATION_MISMATCH")
            return stored
