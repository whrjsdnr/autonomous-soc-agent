"""Saved journal/normalized authentication transport and witnessed five-minute windows.

No host log reader is invoked. Existing native parsers provide syntax, not authenticity.
"""

from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from soc_agent.security_ai.authentication import (
    AuthenticationEvent,
    AuthenticationWindowExtractor,
    authentication_record,
)
from soc_agent.security_ai.features import SourceReference
from soc_agent.security_ai.operational.native_authentication import project_journal
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import AuthenticationWindowJob


def normalized(row: dict, source: str):
    """Stable identity across retries; saved journald is DECLARED, never native attestation."""
    if set(row) == {"journal"}:
        event = project_journal(row["journal"])
        fields = dict(event.normalized_fields)
        if fields["parse_status"] != "MAPPED_AUTHENTICATION":
            raise ValueError("CONTINUOUS_AUTH_NOT_INFERABLE")
        value = AuthenticationEvent(
            event_id=str(event.event_id),
            event_time=event.event_timestamp,
            account_id=fields["account_id"],
            source_identifier=fields["source_identifier"],
            authentication_result=fields["authentication_result"],
        )
        cursor = event.source.record
    elif set(row) == {"event", "cursor"}:
        value = AuthenticationEvent.model_validate(row["event"])
        cursor = row["cursor"]
    else:
        raise ValueError("CONTINUOUS_AUTH_TRANSPORT_SCHEMA")
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096:
        raise ValueError("CONTINUOUS_AUTH_CURSOR_BOUND")
    record = authentication_record(
        value,
        source=SourceReference(
            source_type="stream",
            source_name="continuous-saved-auth:" + source,
            source_version="1",
            record_id=value.event_id,
        ),
    )
    record = record.model_copy(
        update={"record_id": uuid5(NAMESPACE_URL, source + ":" + value.event_id)}
    )
    return cursor, record


class AuthenticationWindows:
    def __init__(self, packages, *, origin="DECLARED_STORED_RECORDS", limit=4096):
        self.packages = packages
        self.origin = origin
        self.limit = limit
        self.records = {}
        self.maximum = None
        self.emitted = set()
        self.partial = 0

    def observe(self, record, *, source_digest: str):
        stamp = record.observed_at
        if self.maximum and stamp < self.maximum:
            raise ValueError("CONTINUOUS_AUTH_ORDER_REVERSED")
        self.maximum = stamp
        output = self.advance(stamp, source_digest=source_digest)
        if len(self.records) >= self.limit:
            raise ValueError("CONTINUOUS_AUTH_WINDOW_CAPACITY")
        identity = str(record.record_id)
        if identity in self.records and self.records[identity] != record:
            raise ValueError("CONTINUOUS_AUTH_EVENT_REUSE")
        self.records[identity] = record
        return output

    def advance(self, watermark: datetime, *, source_digest: str):
        if self.maximum and watermark < self.maximum:
            raise ValueError("CONTINUOUS_AUTH_WATERMARK_REGRESSION")
        self.maximum = watermark
        if not self.records:
            return []
        windows = AuthenticationWindowExtractor().extract(tuple(self.records.values()))
        output = []
        for window in windows:
            if window.ended_at > watermark:
                continue
            selected = tuple(
                r
                for r in self.records.values()
                if r.payload()["account_id"] == window.account_id
                and window.started_at <= r.observed_at < window.ended_at
            )
            key = digest(dict(events=[str(r.record_id) for r in selected], source=source_digest))
            if key not in self.emitted:
                output.append(
                    AuthenticationWindowJob(
                        kind="authentication_window",
                        origin=self.origin,
                        records=selected,
                        packages=self.packages,
                        witness=watermark,
                        quality="ELIGIBLE",
                        source_sha256=source_digest,
                    )
                )
                self.emitted.add(key)
            for record in selected:
                self.records.pop(str(record.record_id))
        # Dedup of finished windows is durable at handoff, not an unbounded RAM set.
        if len(self.emitted) > 1024:
            self.emitted.clear()
        return output

    def close(self, source_digest):
        if not self.records:
            return []
        self.partial += 1
        result = AuthenticationWindowJob(
            kind="authentication_window",
            origin=self.origin,
            records=tuple(self.records.values()),
            packages=self.packages,
            witness=self.maximum or datetime(1970, 1, 1, tzinfo=UTC),
            quality="INCOMPLETE",
            source_sha256=source_digest,
        )
        self.records.clear()
        return [result]


def validate_window(job):
    if job.quality != "ELIGIBLE":
        return job.quality
    windows = AuthenticationWindowExtractor().extract(job.records)
    if not windows or any(w.ended_at > job.witness for w in windows):
        return "INCOMPLETE"
    # Explicit five-minute schema from existing extractor, no invented feature list.
    if any(w.ended_at - w.started_at != timedelta(seconds=300) for w in windows):
        return "INVALID"
    return "ELIGIBLE"
