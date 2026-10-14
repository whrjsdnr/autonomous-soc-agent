"""Conservative maintenance planning, not deletion authority or inference permission."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.review.persistence.database import GovernanceDatabase
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.state.evidence import UTCTimestamp, utc_now


class RetentionDenied(ValueError):
    pass


class RetentionItem(Snapshot):
    kind: Literal["QUEUE", "SOURCE", "WINDOW", "CURSOR"]
    reference_digest: Hash
    record_digest: Hash
    eligible: Literal[False] = False
    reasons: tuple[str, ...] = Field(min_length=1)


class RetentionPlan(Snapshot):
    contract_version: Literal["soc-auth-retention-plan:v1"] = "soc-auth-retention-plan:v1"
    binding_digest: Hash
    inventory_digest: Hash
    reference_integrity: Literal["VALIDATED_LOCAL", "UNVERIFIABLE"]
    items: tuple[RetentionItem, ...]
    eligible_count: Literal[0] = 0
    protected_count: int = Field(ge=0)
    deleted_count: Literal[0] = 0
    automatic_cleanup: Literal[False] = False
    retention_period_days: None = None
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consistent_inventory(self):
        if self.protected_count != len(
            self.items
        ) or self.inventory_digest != content_digest_payload(
            {"items": [i.model_dump(mode="json") for i in self.items]}
        ):
            raise ValueError("RETENTION_INVENTORY_REJECTED")
        return self


class MaintenanceEntry(Snapshot):
    sequence: int = Field(strict=True, gt=0)
    binding: Hash
    previous: Hash
    operation: Literal[
        "RETENTION_DRY_RUN",
        "CLEANUP_DENIED",
        "COLLECTION_START",
        "COLLECTION_RESULT",
        "CAPACITY_OBSERVATION",
    ]
    status: Literal[
        "DRY_RUN",
        "DENIED",
        "STARTED",
        "INITIAL_READ",
        "RESUMED_EXACT",
        "RESUMED_WITH_REPLAY",
        "GAP_DETECTED",
        "CURSOR_INVALID",
        "PERMISSION_DENIED",
        "SOURCE_UNAVAILABLE",
        "BACKPRESSURE",
        "STORE_FAILURE",
        "NORMAL",
        "WARNING",
        "CRITICAL",
        "UNKNOWN",
    ]
    summary_digest: Hash
    recorded_at: UTCTimestamp = Field(default_factory=utc_now)


class MaintenanceLog:
    """Explicit separate private observer database. Existing SOC schemas/chains untouched.

    Caller holds the pipeline writer lock. Hash chain is local corruption detection,
    not cryptographic authenticity against a privileged writer.
    """

    def __init__(self, path: Path, pipeline: AuthenticationPipeline):
        self.database = GovernanceDatabase(path)
        self.binding = pipeline.digest
        with self.database.transaction(write=False) as c:
            row = c.execute("SELECT version,binding FROM auth_maintenance_config").fetchall()
            if [tuple(r) for r in row] != [(1, self.binding)]:
                raise RetentionDenied("MAINTENANCE_BINDING_REJECTED")
            self._entries(c)

    @classmethod
    def create(cls, path: Path, pipeline: AuthenticationPipeline):
        create_private_directory(path.parent)
        db = GovernanceDatabase.create(path)
        with db.transaction() as c:
            c.execute("CREATE TABLE auth_maintenance_config(version INTEGER,binding TEXT)")
            c.execute("INSERT INTO auth_maintenance_config VALUES(1,?)", (pipeline.digest,))
            c.execute(
                "CREATE TABLE auth_maintenance_events(sequence INTEGER PRIMARY KEY,"
                "payload TEXT NOT NULL,digest TEXT NOT NULL)"
            )
        return cls(path, pipeline)

    def _entries(self, c):
        previous = "0" * 64
        entries = []
        for index, row in enumerate(
            c.execute("SELECT * FROM auth_maintenance_events ORDER BY sequence"), 1
        ):
            try:
                body = MaintenanceEntry.model_validate_json(row["payload"]).model_dump(mode="json")
                if (
                    row["sequence"] != index
                    or set(body)
                    != {
                        "sequence",
                        "binding",
                        "previous",
                        "operation",
                        "status",
                        "summary_digest",
                        "recorded_at",
                    }
                    or body["sequence"] != index
                    or body["binding"] != self.binding
                    or body["previous"] != previous
                    or row["digest"] != content_digest_payload(body)
                ):
                    raise ValueError
                if body["operation"] not in (
                    "RETENTION_DRY_RUN",
                    "CLEANUP_DENIED",
                    "COLLECTION_START",
                    "COLLECTION_RESULT",
                    "CAPACITY_OBSERVATION",
                ):
                    raise ValueError
                previous = row["digest"]
                entries.append(body)
            except (ValueError, TypeError, KeyError) as error:
                raise RetentionDenied("MAINTENANCE_CHAIN_REJECTED") from error
        return tuple(entries)

    def entries(self):
        with self.database.transaction(write=False) as c:
            return self._entries(c)

    def health_counts(self) -> dict[str, int]:
        entries = self.entries()
        pending = False
        interrupted = 0
        for entry in entries:
            if entry["operation"] == "COLLECTION_START":
                interrupted += int(pending)
                pending = True
            elif entry["operation"] == "COLLECTION_RESULT":
                if not pending:
                    raise RetentionDenied("MAINTENANCE_COLLECTION_ORDER_REJECTED")
                pending = False
        return {
            "journal_gap_count": sum(e["status"] == "GAP_DETECTED" for e in entries),
            "cursor_resume_failures": sum(
                e["status"] in ("GAP_DETECTED", "CURSOR_INVALID") for e in entries
            ),
            "collection_outcome_unknown": interrupted + int(pending),
        }

    def append(self, operation: str, status: str, summary_digest: str):
        if operation not in (
            "RETENTION_DRY_RUN",
            "CLEANUP_DENIED",
            "COLLECTION_START",
            "COLLECTION_RESULT",
            "CAPACITY_OBSERVATION",
        ):
            raise RetentionDenied("MAINTENANCE_OPERATION_REJECTED")
        if status not in (
            "DRY_RUN",
            "DENIED",
            "STARTED",
            "INITIAL_READ",
            "RESUMED_EXACT",
            "RESUMED_WITH_REPLAY",
            "GAP_DETECTED",
            "CURSOR_INVALID",
            "PERMISSION_DENIED",
            "SOURCE_UNAVAILABLE",
            "BACKPRESSURE",
            "STORE_FAILURE",
            "NORMAL",
            "WARNING",
            "CRITICAL",
            "UNKNOWN",
        ):
            raise RetentionDenied("MAINTENANCE_STATUS_REJECTED")
        # Only hash summaries are persisted: no raw events, cursors, credentials or error text.
        from pydantic import TypeAdapter

        TypeAdapter(Hash).validate_python(summary_digest)
        with self.database.transaction() as c:
            rows = self._entries(c)
            previous = c.execute(
                "SELECT digest FROM auth_maintenance_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            body = {
                "sequence": len(rows) + 1,
                "binding": self.binding,
                "previous": previous[0] if previous else "0" * 64,
                "operation": operation,
                "status": status,
                "summary_digest": summary_digest,
            }
            body = MaintenanceEntry.model_validate(body).model_dump(mode="json")
            digest = content_digest_payload(body)
            c.execute(
                "INSERT INTO auth_maintenance_events VALUES(?,?,?)",
                (len(rows) + 1, json.dumps(body, sort_keys=True), digest),
            )
        return digest


def retention_plan(pipeline: AuthenticationPipeline, *, audit: MaintenanceLog) -> RetentionPlan:
    if audit.binding != pipeline.digest:
        raise RetentionDenied("MAINTENANCE_BINDING_REJECTED")
    errors = ()
    try:
        read_authentication_view(pipeline)
        integrity = "VALIDATED_LOCAL"
    except (ValueError, OSError, RuntimeError):
        integrity = "UNVERIFIABLE"
        errors = ("LOCAL_REFERENCE_VALIDATION_FAILED",)
    items = []
    with pipeline.queue.database.transaction(write=False) as c:
        pipeline._binding(c)
        for row in c.execute("SELECT * FROM realtime_events ORDER BY event_id"):
            reasons = (
                ("INCOMPLETE_OR_POISON",)
                if row["status"] != "DONE"
                else ("RECOVERY_DEDUP_OR_EVIDENCE_REFERENCE", "EXTERNAL_REFERENCES_UNKNOWN")
            )
            if row["attempts"] > 1:
                reasons += ("RETRY_HISTORY",)
            items.append(
                RetentionItem(
                    kind="QUEUE",
                    record_digest=content_digest_payload(dict(row)),
                    reference_digest=content_digest_payload({"event": row["event_id"]}),
                    reasons=reasons,
                )
            )
        for row in c.execute("SELECT * FROM realtime_cursors ORDER BY source"):
            try:
                pipeline.queue.cursor(row["source"])
            except (ValueError, OSError, RuntimeError):
                integrity = "UNVERIFIABLE"
                errors = ("LOCAL_REFERENCE_VALIDATION_FAILED",)
            items.append(
                RetentionItem(
                    kind="CURSOR",
                    record_digest=content_digest_payload(dict(row)),
                    reference_digest=content_digest_payload({"collector": row[0]}),
                    reasons=("NO_CURSOR_RESET",),
                )
            )
    with pipeline.store.database.transaction(write=False) as c:
        for row in c.execute("SELECT * FROM operational_sources ORDER BY source_key"):
            items.append(
                RetentionItem(
                    kind="SOURCE",
                    record_digest=content_digest_payload(dict(row)),
                    reference_digest=content_digest_payload({"source": row[0]}),
                    reasons=(
                        "INCIDENT_BOUND",
                        "PROVENANCE_REQUIRED",
                        "EXTERNAL_REFERENCES_UNKNOWN",
                    ),
                )
            )
        for row in c.execute("SELECT * FROM operational_auth_windows ORDER BY window_key"):
            items.append(
                RetentionItem(
                    kind="WINDOW",
                    record_digest=content_digest_payload(dict(row)),
                    reference_digest=content_digest_payload({"window": row[0]}),
                    reasons=(
                        "INCIDENT_BOUND",
                        "INVESTIGATION_STATUS_UNKNOWN",
                        "PROVENANCE_REQUIRED",
                    ),
                )
            )
    body = [i.model_dump(mode="json") for i in items]
    plan = RetentionPlan(
        binding_digest=pipeline.digest,
        inventory_digest=content_digest_payload({"items": body}),
        reference_integrity=integrity,
        items=tuple(items),
        protected_count=len(items),
        errors=errors,
    )
    audit.append(
        "RETENTION_DRY_RUN", "DRY_RUN", content_digest_payload(plan.model_dump(mode="json"))
    )
    return plan


def deny_cleanup(plan: RetentionPlan, *, audit: MaintenanceLog) -> None:
    """No delete API: even an arbitrary approval-shaped JSON is not authority.

    Enable execution only in a future reviewed cross-store reference/authorization contract.
    """
    if plan.binding_digest != audit.binding:
        raise RetentionDenied("MAINTENANCE_BINDING_REJECTED")
    audit.append("CLEANUP_DENIED", "DENIED", content_digest_payload(plan.model_dump(mode="json")))
    raise RetentionDenied("CLEANUP_NOT_AUTHORIZED_REFERENCES_PROTECTED")


def storage_metrics(pipeline: AuthenticationPipeline) -> dict[str, object]:
    """Measured local snapshots; no claim about transient peak latency or unobservable caches."""
    now = datetime.now(UTC)
    with pipeline.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT * FROM realtime_events").fetchall()
        events = [pipeline.queue._decode(row) for row in rows]
        pending = [
            e for e, r in zip(events, rows, strict=True) if r["status"] in ("PENDING", "CLAIMED")
        ]
        provenance = 0
        for row in rows:
            if row["status"] == "DONE":
                payload = json.loads(row["outcome"])["workflow"]["receipt"]
                provenance += int("provenance" in payload) + len(
                    payload.get("window_provenance", [])
                )
    with pipeline.store.database.transaction(write=False) as c:
        sources = c.execute("SELECT count(*) FROM operational_sources").fetchone()[0]
        windows = c.execute("SELECT count(*) FROM operational_auth_windows").fetchone()[0]
    paths = (pipeline.queue.database.path, pipeline.store.database.path)
    return {
        "queue_depth": len(pending),
        "oldest_pending_age_seconds": max(
            ((now - e.ingestion_timestamp).total_seconds() for e in pending), default=0
        ),
        "sqlite_database_size_bytes": sum(p.stat().st_size for p in paths),
        "sqlite_wal_size_bytes": sum(
            Path(str(p) + "-wal").stat().st_size for p in paths if Path(str(p) + "-wal").exists()
        ),
        "source_record_count": sources,
        "window_record_count": windows,
        "provenance_record_count": provenance,
        "retention_eligible_count": 0,
        "retention_protected_queue_count": len(rows),
    }
