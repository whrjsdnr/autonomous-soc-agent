"""Observed intake failures, no cursor reset, seek fallback, delete or model authorization."""

from typing import Literal

from soc_agent.realtime.collectors import CollectorUnavailable, CursorUnavailable
from soc_agent.realtime.queue import QueueFull, QueueIntegrityError
from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.retention import MaintenanceLog, RetentionDenied


class CollectionHealth(Snapshot):
    contract_version: Literal["soc-auth-journal-health:v1"] = "soc-auth-journal-health:v1"
    status: Literal[
        "INITIAL_READ",
        "RESUMED_EXACT",
        "RESUMED_WITH_REPLAY",
        "GAP_DETECTED",
        "CURSOR_INVALID",
        "PERMISSION_DENIED",
        "SOURCE_UNAVAILABLE",
        "BACKPRESSURE",
        "STORE_FAILURE",
    ]
    accepted_count: int | None = None
    batch_record_count: int | None = None
    cursor_digest: Hash | None = None
    gap_extent: Literal["UNKNOWN", "NOT_APPLICABLE"] = "NOT_APPLICABLE"
    continuation_allowed: bool = False
    audit_digest: Hash


def collect_with_health(
    pipeline: AuthenticationPipeline,
    collector: LinuxAuthenticationCollector,
    *,
    audit: MaintenanceLog,
    limit: int = 16,
) -> CollectionHealth:
    """Call under the existing exclusive writer lock. Separate observer commit is explicit.

    Audit failure propagates: never report healthy on absent audit. Already committed queue
    data/cursor remains durable and must be reconciled, not rolled back across databases.
    """
    if audit.binding != pipeline.digest:
        raise RetentionDenied("MAINTENANCE_BINDING_REJECTED")
    audit.append("COLLECTION_START", "STARTED", pipeline.digest)
    cursor = None
    accepted = None
    count = None
    before = None
    gap = "NOT_APPLICABLE"
    try:
        before = sum(pipeline.queue.counts().values())
        cursor = pipeline.queue.cursor(pipeline.binding["collector"])
        if cursor is None and pipeline.queue.counts():
            raise QueueIntegrityError("Missing existing collector cursor")
        count = pipeline.collect(collector, limit=limit)
        status = "RESUMED_EXACT" if cursor else "INITIAL_READ"

    except CursorUnavailable:
        status = "GAP_DETECTED" if cursor else "CURSOR_INVALID"
        gap = "UNKNOWN"
    except CollectorUnavailable as error:
        status = (
            "PERMISSION_DENIED"
            if str(error).startswith("PERMISSION_DENIED:")
            else "SOURCE_UNAVAILABLE"
        )
    except QueueFull:
        status = "BACKPRESSURE"  # partial earlier batch commits remain retained
    except QueueIntegrityError:
        status = "CURSOR_INVALID"
        gap = "UNKNOWN"
    except (StorageError, OSError, RuntimeError):
        status = "STORE_FAILURE"
    except ValueError:
        status = "SOURCE_UNAVAILABLE"
    retained = None
    try:
        if before is not None:
            accepted = sum(pipeline.queue.counts().values()) - before
        if status not in ("STORE_FAILURE", "CURSOR_INVALID"):
            retained = pipeline.queue.cursor(pipeline.binding["collector"])
    except QueueIntegrityError:
        status, gap = "CURSOR_INVALID", "UNKNOWN"
    except (StorageError, OSError, RuntimeError):
        status, accepted = "STORE_FAILURE", None
    if (
        status == "RESUMED_EXACT"
        and count is not None
        and accepted is not None
        and accepted < count
    ):
        status = "RESUMED_WITH_REPLAY"
    digest = content_digest_payload(
        {"status": status, "batch_records": count, "accepted_count": accepted, "gap_extent": gap}
    )
    entry = audit.append("COLLECTION_RESULT", status, digest)
    return CollectionHealth(
        status=status,
        accepted_count=accepted,
        batch_record_count=count,
        cursor_digest=retained.source_digest if retained else None,
        gap_extent=gap,
        continuation_allowed=status in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY"),
        audit_digest=entry,
    )
