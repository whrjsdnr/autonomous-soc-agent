"""At-least-once journal intake into isolated authentication aggregation, never actions."""

from sqlite3 import Connection
from uuid import UUID

from soc_agent.realtime.queue import EventQueue
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.native_authentication import (
    COLLECTOR,
    PAM_COLLECTOR,
    LinuxAuthenticationCollector,
    NativeAuthenticationReceipt,
    ingest_authentication,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


class AuthenticationPipeline:
    """Caller holds an exclusive service lock when using EventQueue.recover().

    Two databases: queue commit publishes the cursor only after durable retention;
    source commit precedes queue acknowledgement. Crash between commits replays with
    Source Store deduplication. No exactly-once or cross-database atomicity claim.
    """

    def __init__(
        self,
        queue: EventQueue,
        store: OperationalSourceStore,
        incident_id: UUID,
        *,
        collector_identity: str = LinuxAuthenticationCollector.identity,
    ) -> None:
        if collector_identity not in (
            LinuxAuthenticationCollector.identity,
            "linux:journal:authentication:pam-failure:v1",
        ):
            raise ValueError("AUTH_COLLECTOR_IDENTITY_REJECTED")
        self.queue, self.store, self.incident_id = queue, store, incident_id
        self.binding = {
            "contract_version": "soc-auth-pipeline-binding:v1",
            "queue_store_id": str(queue.database.store_id),
            "source_store_id": str(store.database.store_id),
            "incident_id": str(incident_id),
            "collector": collector_identity,
        }
        self.digest = content_digest_payload(self.binding)
        with queue.database.transaction() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS native_auth_binding(id INTEGER PRIMARY KEY "
                "CHECK(id=1),payload TEXT NOT NULL,digest TEXT NOT NULL)"
            )
            rows = c.execute("SELECT * FROM native_auth_binding").fetchall()
            if not rows:
                if c.execute("SELECT count(*) FROM realtime_events").fetchone()[0]:
                    raise ValueError("UNBOUND_AUTH_QUEUE_NOT_ADOPTED")
                import json

                c.execute(
                    "INSERT INTO native_auth_binding VALUES(1,?,?)",
                    (json.dumps(self.binding, sort_keys=True), self.digest),
                )
            self._binding(c)

    def _binding(self, connection: Connection) -> None:
        import json

        rows = connection.execute("SELECT * FROM native_auth_binding").fetchall()
        if len(rows) != 1:
            raise ValueError("AUTH_PIPELINE_BINDING_MISSING")
        try:
            binding = json.loads(rows[0]["payload"])
            if (
                binding != self.binding
                or rows[0]["digest"] != self.digest
                or content_digest_payload(binding) != self.digest
            ):
                raise ValueError
        except (ValueError, TypeError) as error:
            raise ValueError("AUTH_PIPELINE_BINDING_MISMATCH") from error

    def collect(self, collector: LinuxAuthenticationCollector, *, limit: int = 16) -> int:
        if (
            type(collector) is not LinuxAuthenticationCollector
            or collector.identity != self.binding["collector"]
        ):
            raise ValueError("AUTH_COLLECTOR_TYPE_REJECTED")
        with self.queue.database.transaction(write=False) as c:
            self._binding(c)
        events = collector.poll(self.queue.cursor(collector.identity), limit)
        for event in events:
            self.queue.enqueue(event, cursor_source=collector.identity)
        return len(events)

    def step(self) -> NativeAuthenticationReceipt | str:
        with self.queue.database.transaction(write=False) as c:
            self._binding(c)
        claim = self.queue.claim()
        if claim is None:
            return "IDLE"
        try:
            expected_collector = (
                PAM_COLLECTOR
                if self.binding["collector"] == "linux:journal:authentication:pam-failure:v1"
                else COLLECTOR
            )
            if claim.event.collector_id != expected_collector:
                raise ValueError("AUTH_QUEUE_COLLECTOR_BINDING_MISMATCH")
            receipt = ingest_authentication(
                claim.event,
                expected_event_digest=claim.event.source_digest,
                store=self.store,
                incident_id=self.incident_id,
            )
            payload = (
                receipt.model_dump(mode="json")
                if receipt
                else {
                    "status": "NOT_INFERABLE",
                    "event_id": str(claim.event.event_id),
                    "source_digest": claim.event.source_digest,
                }
            )
            self.queue.finish(
                claim,
                {
                    "inference": "NOT_INFERABLE",
                    "incident_id": str(self.incident_id),
                    "human_boundary": "WRITE_DENIED",
                    "workflow": {"receipt": payload, "digest": content_digest_payload(payload)},
                },
            )
            return receipt or "NOT_INFERABLE"
        except (ValueError, OSError, RuntimeError):
            # Fixed category, no message/credential dumped; existing finite retry/poison policy.
            self.queue.fail(claim, "INVALID_INPUT")
            raise
