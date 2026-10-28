"""Existing journal collector interface → durable cursor queue → declared auth events.

No default collector is constructed. Host collection must be supplied by an
explicitly authorized service composition; tests supply stored/mock readers only.
"""

from pathlib import Path
from typing import Protocol

from soc_agent.realtime.models import CommonEvent
from soc_agent.realtime.queue import EventQueue
from soc_agent.security_ai.authentication import AuthenticationEvent


class JournalReader(Protocol):
    identity: str

    def poll(self, cursor: CommonEvent | None, limit: int) -> list[CommonEvent]: ...


class JournalTransport:
    def __init__(self, directory: Path, reader: JournalReader, *, capacity=32):
        self.reader = reader
        self.queue = (
            EventQueue(directory / "journal-queue.sqlite", capacity=capacity, retry_limit=3)
            if (directory / "journal-queue.sqlite").exists()
            else EventQueue.create(
                directory / "journal-queue.sqlite", capacity=capacity, retry_limit=3
            )
        )

    def poll(self, *, limit=16):
        if not 1 <= limit <= 32:
            raise ValueError("CONTINUOUS_JOURNAL_BATCH_BOUND")
        cursor = self.queue.cursor(self.reader.identity)
        events = self.reader.poll(cursor, limit)
        if len(events) > limit:
            raise ValueError("CONTINUOUS_JOURNAL_READER_BOUND")
        for event in events:
            # Existing EventQueue atomically retains the event before publishing cursor.
            self.queue.enqueue(event, cursor_source=self.reader.identity)
        return len(events)

    def claim(self):
        held = self.queue.claim()
        if held is None:
            return None
        fields = dict(held.event.normalized_fields)
        try:
            if fields.get("parse_status") != "MAPPED_AUTHENTICATION":
                raise ValueError("CONTINUOUS_JOURNAL_NOT_INFERABLE")
            event = AuthenticationEvent(
                event_id=str(held.event.event_id),
                event_time=held.event.event_timestamp,
                account_id=fields["account_id"],
                source_identifier=fields["source_identifier"],
                authentication_result=fields["authentication_result"],
            )
            return held, dict(event=event.model_dump(mode="json"), cursor=held.event.source.record)
        except (ValueError, KeyError):
            self.queue.fail(held, "INVALID_INPUT")
            raise

    def acknowledge_retained(self, held):
        # Caller has committed this input to Continuous ingress before this ACK.
        self.queue.finish(
            held,
            dict(
                inference="NOT_INFERABLE",
                workflow="DURABLY_HANDED_OFF",
                human_boundary="WRITE_DENIED",
            ),
        )

    def recover(self):
        # Caller holds the service lifetime lock. Interrupted handoffs are safe
        # to deliver again: event identity and Continuous ingress are idempotent.
        self.queue.recover()


class StoredJournalReader:
    """Pinned saved journal input, never journalctl or host log access."""

    def __init__(self, path: Path, sha256: str):
        import hashlib
        import json

        from soc_agent.security_ai.operational.native_authentication import project_journal
        from soc_agent.security_ai.research.environment import read_local

        body = read_local(path, 16 * 1024**2)
        if hashlib.sha256(body).hexdigest() != sha256 or not body.endswith(b"\n"):
            raise ValueError("CONTINUOUS_SAVED_JOURNAL_INTEGRITY")
        rows = body.splitlines()
        if len(rows) > 16384:
            raise ValueError("CONTINUOUS_SAVED_JOURNAL_BOUND")
        self.identity = "stored-journal:" + sha256
        self.events = tuple(project_journal(json.loads(row)) for row in rows)
        self.positions = {str(event.event_id): i for i, event in enumerate(self.events)}
        if len(self.positions) != len(self.events):
            raise ValueError("CONTINUOUS_JOURNAL_DUPLICATE")

    def poll(self, cursor, limit):
        if cursor is None:
            position = 0
        elif str(cursor.event_id) in self.positions:
            position = self.positions[str(cursor.event_id)] + 1
        else:
            raise ValueError("CONTINUOUS_JOURNAL_CURSOR_UNAVAILABLE")
        return list(self.events[position : position + limit])
