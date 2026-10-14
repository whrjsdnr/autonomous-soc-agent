"""Capacity observations with nullable unknowns, never control or archive authority."""

import json
import os
import shutil
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import NativeAuthenticationReceipt
from soc_agent.security_ai.operational.retention import MaintenanceLog, RetentionDenied
from soc_agent.state.evidence import UTCTimestamp, utc_now

Status = Literal["NORMAL", "WARNING", "CRITICAL", "UNKNOWN"]


class CapacityMetrics(Snapshot):
    queue_depth: int | None = Field(default=None, ge=0)
    queue_pending_count: int | None = Field(default=None, ge=0)
    queue_retry_count: int | None = Field(default=None, ge=0)
    queue_poison_count: int | None = Field(default=None, ge=0)
    oldest_pending_age_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    sqlite_database_bytes: int | None = Field(default=None, ge=0)
    sqlite_wal_bytes: int | None = Field(default=None, ge=0)
    sqlite_freelist_pages: int | None = Field(default=None, ge=0)
    source_record_count: int | None = Field(default=None, ge=0)
    window_record_count: int | None = Field(default=None, ge=0)
    provenance_record_count: int | None = Field(default=None, ge=0)
    available_disk_bytes: int | None = Field(default=None, ge=0)
    rss_memory_mb: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    errors: tuple[str, ...] = ()


class ExampleThresholds(Snapshot):
    """Illustrative values only. No production SLO or automatic backpressure tuning."""

    queue_warning: int = Field(default=128, gt=0)
    queue_critical: int = Field(default=224, gt=0)
    pending_warning_seconds: float = Field(default=300, gt=0, allow_inf_nan=False)
    pending_critical_seconds: float = Field(default=900, gt=0, allow_inf_nan=False)
    database_warning_bytes: int = Field(default=256 * 2**20, gt=0)
    database_critical_bytes: int = Field(default=512 * 2**20, gt=0)
    wal_warning_bytes: int = Field(default=16 * 2**20, gt=0)
    wal_critical_bytes: int = Field(default=64 * 2**20, gt=0)
    disk_warning_bytes: int = Field(default=512 * 2**20, gt=0)
    disk_critical_bytes: int = Field(default=128 * 2**20, gt=0)
    rss_warning_mb: float = Field(default=512, gt=0, allow_inf_nan=False)
    rss_critical_mb: float = Field(default=1024, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def ordered(self):
        for low, high in [
            (self.queue_warning, self.queue_critical),
            (self.pending_warning_seconds, self.pending_critical_seconds),
            (self.database_warning_bytes, self.database_critical_bytes),
            (self.wal_warning_bytes, self.wal_critical_bytes),
            (self.rss_warning_mb, self.rss_critical_mb),
        ]:
            if low > high:
                raise ValueError("CAPACITY_THRESHOLDS_REJECTED")
        if self.disk_critical_bytes > self.disk_warning_bytes:
            raise ValueError("CAPACITY_THRESHOLDS_REJECTED")
        return self


class Finding(Snapshot):
    metric: str
    status: Status
    reason: Literal[
        "THRESHOLD",
        "MEASUREMENT_MISSING",
        "MEASUREMENT_PRESENT",
        "INCREASED",
        "COMPARISON_UNAVAILABLE",
    ]
    delta: float | None = Field(default=None, allow_inf_nan=False)


class CapacityObservation(Snapshot):
    contract_version: Literal["soc-auth-capacity-observation:v1"] = (
        "soc-auth-capacity-observation:v1"
    )
    binding_digest: Hash
    metrics: CapacityMetrics
    thresholds: ExampleThresholds
    status: Status
    findings: tuple[Finding, ...]
    observation_digest: Hash
    measured_at: UTCTimestamp = Field(default_factory=utc_now)
    automatic_action: Literal[False] = False

    def core(self):
        return self.model_dump(mode="json", exclude={"observation_digest", "measured_at"})

    @model_validator(mode="after")
    def intact(self):
        if self.observation_digest != content_digest_payload(self.core()):
            raise ValueError("CAPACITY_DIGEST_REJECTED")
        expected = tuple(metric_findings(self.metrics, self.thresholds))
        if self.findings[: len(expected)] != expected or self.status != overall_status(
            self.findings
        ):
            raise ValueError("CAPACITY_ASSESSMENT_REJECTED")
        return self


def overall_status(findings) -> Status:
    statuses = {f.status for f in findings}
    return (
        "CRITICAL"
        if "CRITICAL" in statuses
        else "UNKNOWN"
        if "UNKNOWN" in statuses
        else "WARNING"
        if "WARNING" in statuses
        else "NORMAL"
    )


def resident_memory_mb() -> float | None:
    try:
        return (
            int(Path("/proc/self/statm").read_text().split()[1])
            * os.sysconf("SC_PAGE_SIZE")
            / 2**20
        )
    except (OSError, ValueError, IndexError):
        return None


def measure_capacity(pipeline: AuthenticationPipeline) -> CapacityMetrics:
    values = {}
    errors = []
    try:
        with pipeline.queue.database.transaction(write=False) as c:
            pipeline._binding(c)
            rows = c.execute("SELECT * FROM realtime_events").fetchall()
            pending = [
                pipeline.queue._decode(r) for r in rows if r["status"] in ("PENDING", "CLAIMED")
            ]
            ages = [(utc_now() - e.ingestion_timestamp).total_seconds() for e in pending]
            values.update(
                queue_depth=len(pending),
                queue_pending_count=sum(r["status"] == "PENDING" for r in rows),
                queue_retry_count=sum(
                    (
                        (r["status"] == "PENDING" and r["attempts"] > 0)
                        or (r["status"] == "CLAIMED" and r["attempts"] > 1)
                    )
                    for r in rows
                ),
                queue_poison_count=sum(r["status"] == "POISON" for r in rows),
            )
            values["oldest_pending_age_seconds"] = (
                max(ages, default=0) if all(a >= 0 for a in ages) else None
            )
            provenance = 0
            for r in rows:
                if r["status"] == "DONE":
                    body = json.loads(r["outcome"])["workflow"]["receipt"]
                    if not isinstance(body, dict):
                        raise ValueError("CAPACITY_RECEIPT_SHAPE_REJECTED")
                    if "contract_version" in body:
                        receipt = NativeAuthenticationReceipt.model_validate(body)
                        provenance += 1 + len(receipt.window_provenance)
                    elif (
                        set(body) != {"status", "event_id", "source_digest"}
                        or body["status"] != "NOT_INFERABLE"
                    ):
                        raise ValueError("CAPACITY_RECEIPT_SHAPE_REJECTED")
            values["provenance_record_count"] = provenance
    except (StorageError, ValueError, OSError, RuntimeError, TypeError, KeyError):
        errors.append("QUEUE_MEASUREMENT_FAILED")
        for k in (
            "queue_depth",
            "queue_pending_count",
            "queue_retry_count",
            "queue_poison_count",
            "oldest_pending_age_seconds",
            "provenance_record_count",
        ):
            values[k] = None
    try:
        with pipeline.store.database.transaction(write=False) as c:
            values["source_record_count"] = c.execute(
                "SELECT count(*) FROM operational_sources"
            ).fetchone()[0]
            values["window_record_count"] = c.execute(
                "SELECT count(*) FROM operational_auth_windows"
            ).fetchone()[0]
    except (StorageError, ValueError, OSError, RuntimeError):
        errors.append("SOURCE_MEASUREMENT_FAILED")
    paths = (pipeline.queue.database.path, pipeline.store.database.path)
    try:
        values["sqlite_database_bytes"] = sum(p.stat().st_size for p in paths)
        values["sqlite_wal_bytes"] = sum(
            Path(str(p) + "-wal").stat().st_size for p in paths if Path(str(p) + "-wal").exists()
        )
    except OSError:
        errors.append("FILE_SIZE_MEASUREMENT_FAILED")
    try:
        free = 0
        for db in (pipeline.queue.database, pipeline.store.database):
            with db.transaction(write=False) as c:
                free += c.execute("PRAGMA freelist_count").fetchone()[0]
        values["sqlite_freelist_pages"] = free
    except (StorageError, ValueError, OSError, RuntimeError):
        errors.append("SQLITE_PAGE_MEASUREMENT_FAILED")
    try:
        values["available_disk_bytes"] = min(shutil.disk_usage(p.parent).free for p in paths)
    except OSError:
        errors.append("DISK_MEASUREMENT_FAILED")
    values["rss_memory_mb"] = resident_memory_mb()
    return CapacityMetrics(**values, errors=tuple(errors))


def metric_findings(metrics: CapacityMetrics, limits: ExampleThresholds) -> list[Finding]:
    pairs = {
        "queue_depth": (limits.queue_warning, limits.queue_critical),
        "oldest_pending_age_seconds": (
            limits.pending_warning_seconds,
            limits.pending_critical_seconds,
        ),
        "sqlite_database_bytes": (limits.database_warning_bytes, limits.database_critical_bytes),
        "sqlite_wal_bytes": (limits.wal_warning_bytes, limits.wal_critical_bytes),
        "available_disk_bytes": (limits.disk_warning_bytes, limits.disk_critical_bytes),
        "rss_memory_mb": (limits.rss_warning_mb, limits.rss_critical_mb),
    }
    findings = []
    for name, value in metrics.model_dump(exclude={"errors"}).items():
        status = "NORMAL"
        reason = "MEASUREMENT_PRESENT"
        if value is None:
            status, reason = "UNKNOWN", "MEASUREMENT_MISSING"
        elif name in pairs:
            warn, critical = pairs[name]
            if name == "available_disk_bytes":
                status = (
                    "CRITICAL" if value <= critical else "WARNING" if value <= warn else "NORMAL"
                )
            else:
                status = (
                    "CRITICAL" if value >= critical else "WARNING" if value >= warn else "NORMAL"
                )
            reason = "THRESHOLD"
        findings.append(Finding(metric=name, status=status, reason=reason))
    return findings


def capacity_observation(
    pipeline: AuthenticationPipeline,
    *,
    thresholds: ExampleThresholds | None = None,
    previous: CapacityObservation | None = None,
) -> CapacityObservation:
    metrics = measure_capacity(pipeline)
    limits = thresholds or ExampleThresholds()
    findings = metric_findings(metrics, limits)
    if previous:
        previous = CapacityObservation.model_validate(previous.model_dump())
        for name in ("queue_depth", "sqlite_database_bytes", "sqlite_wal_bytes"):
            value = getattr(metrics, name)
            old = getattr(previous.metrics, name)
            if previous.binding_digest != pipeline.digest or value is None or old is None:
                findings.append(
                    Finding(metric=name, status="UNKNOWN", reason="COMPARISON_UNAVAILABLE")
                )
            elif value > old:
                findings.append(
                    Finding(metric=name, status="NORMAL", reason="INCREASED", delta=value - old)
                )
    status = overall_status(findings)
    core = {
        "contract_version": "soc-auth-capacity-observation:v1",
        "binding_digest": pipeline.digest,
        "metrics": metrics.model_dump(mode="json"),
        "thresholds": limits.model_dump(mode="json"),
        "status": status,
        "findings": [f.model_dump(mode="json") for f in findings],
        "automatic_action": False,
    }
    return CapacityObservation.model_validate(
        core | {"observation_digest": content_digest_payload(core)}
    )


def record_capacity(audit: MaintenanceLog, observation: CapacityObservation) -> str:
    observation = CapacityObservation.model_validate(observation.model_dump())
    if audit.binding != observation.binding_digest:
        raise RetentionDenied("CAPACITY_BINDING_REJECTED")
    return audit.append("CAPACITY_OBSERVATION", observation.status, observation.observation_digest)
