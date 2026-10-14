"""Read-only local contracts, real SQLite; deterministic authentication fixtures."""

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
from tests.authentication_crash_harness import open_pipeline, security_check
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.review.persistence.models import StorageError
from soc_agent.security_ai.operational import capacity as module
from soc_agent.security_ai.operational.archive import (
    ArchiveManifest,
    ArchiveRequest,
    archive_manifest,
)
from soc_agent.security_ai.operational.capacity import (
    CapacityMetrics,
    CapacityObservation,
    ExampleThresholds,
    capacity_observation,
    measure_capacity,
    record_capacity,
)
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    authentication_source,
    project_journal,
)
from soc_agent.security_ai.operational.retention import MaintenanceLog


def configured(tmp_path, *, processed=True):
    p = open_pipeline(tmp_path / "private", LinuxAuthenticationCollector.identity, create=True)
    event = project_journal(row())
    p.queue.enqueue(event, cursor_source=p.binding["collector"])
    if processed:
        p.step()
    source = authentication_source(
        event, expected_event_digest=event.source_digest, incident_id=p.incident_id
    )
    request = ArchiveRequest(
        incident_id=p.incident_id,
        source_event_ids=(event.event_id,),
        expected_source_digests=(source.content_digest,),
    )
    return p, event, request


def test_manifest_determinism_roundtrip_and_protection(tmp_path):
    p, _, request = configured(tmp_path)
    a = archive_manifest(p, request)
    b = archive_manifest(p, request)
    assert (
        a.created_at != b.created_at
        and a.core() == b.core()
        and a.manifest_digest == b.manifest_digest
    )
    assert (
        a.readiness_status == "PROTECTED"
        and a.window_ids
        and a.provenance_references
        and a.source_digests
    )
    assert not a.archive_execution_allowed
    assert ArchiveManifest.model_validate_json(a.model_dump_json()) == a
    assert "fixture-user" not in a.model_dump_json() and "192.0.2.5" not in a.model_dump_json()
    assert asyncio.run(security_check(p))["write_spy_calls"] == 0


@pytest.mark.parametrize(
    "field", ["manifest_digest", "readiness_status", "archive_execution_allowed"]
)
def test_manifest_forged_approval_or_digest_rejected(tmp_path, field):
    p, _, request = configured(tmp_path)
    data = archive_manifest(p, request).model_dump(mode="json")
    data[field] = (
        "0" * 64
        if field == "manifest_digest"
        else "READY_FOR_REVIEW"
        if field == "readiness_status"
        else True
    )
    with pytest.raises(ValueError):
        ArchiveManifest.model_validate(data)
    data = archive_manifest(p, request).model_dump(mode="json")
    data["approval_id"] = str(UUID(int=9))
    with pytest.raises(ValueError):
        ArchiveManifest.model_validate(data)


@pytest.mark.parametrize(
    "damage", ["source_digest", "missing_source", "window", "receipt", "incident", "missing_event"]
)
def test_manifest_failure_statuses(tmp_path, damage):
    p, _, request = configured(tmp_path)
    if damage == "source_digest":
        request = request.model_copy(update={"expected_source_digests": ("0" * 64,)})
    elif damage == "incident":
        request = request.model_copy(update={"incident_id": UUID(int=888)})
    elif damage == "missing_event":
        request = request.model_copy(update={"source_event_ids": (UUID(int=889),)})
    else:
        db = p.queue.database if damage == "receipt" else p.store.database
        with db.transaction() as c:
            if damage == "missing_source":
                c.execute("DELETE FROM operational_sources")
            elif damage == "window":
                c.execute("UPDATE operational_auth_windows SET digest=?", ("0" * 64,))
            else:
                c.execute("UPDATE realtime_events SET outcome='{}'")
    manifest = archive_manifest(p, request)
    assert manifest.readiness_status in ("INTEGRITY_FAILURE", "INCOMPLETE_EVIDENCE", "BLOCKED")
    assert not manifest.archive_execution_allowed


@pytest.mark.parametrize("state", ["PENDING", "RETRY", "POISON"])
def test_incomplete_queue_not_archive_ready(tmp_path, state):
    p, _, request = configured(tmp_path, processed=False)
    if state != "PENDING":
        claim = p.queue.claim()
        p.queue.fail(claim)
        if state == "POISON":
            for _ in range(p.queue.retry_limit - 1):
                claim = p.queue.claim()
                p.queue.fail(claim)
    assert archive_manifest(p, request).readiness_status == "INCOMPLETE_EVIDENCE"
    if state == "RETRY":
        assert measure_capacity(p).queue_retry_count == 1
    elif state == "POISON":
        assert measure_capacity(p).queue_poison_count == 1


def test_duplicate_archive_targets_rejected(tmp_path):
    _, event, request = configured(tmp_path)
    with pytest.raises(ValueError):
        ArchiveRequest(
            incident_id=request.incident_id,
            source_event_ids=(event.event_id, event.event_id),
            expected_source_digests=request.expected_source_digests * 2,
        )


def test_capacity_actual_sqlite_and_readonly_digest(tmp_path):
    p, _, _ = configured(tmp_path)
    metrics = measure_capacity(p)
    assert metrics.queue_depth == metrics.queue_poison_count == metrics.queue_retry_count == 0
    assert metrics.source_record_count == metrics.window_record_count == 1
    assert metrics.provenance_record_count == 2
    assert metrics.sqlite_database_bytes == sum(
        db.path.stat().st_size for db in (p.queue.database, p.store.database)
    )
    assert metrics.sqlite_wal_bytes == 0 and metrics.available_disk_bytes > 0
    a = capacity_observation(p)
    assert CapacityObservation.model_validate_json(a.model_dump_json()) == a
    data = a.model_dump(mode="json")
    data["status"] = "CRITICAL" if a.status != "CRITICAL" else "NORMAL"
    with pytest.raises(ValueError):
        CapacityObservation.model_validate(data)


def complete_metrics(**updates):
    body = {k: 0 for k in CapacityMetrics.model_fields if k != "errors"}
    body.update(available_disk_bytes=2**40, rss_memory_mb=1)
    return CapacityMetrics(**(body | updates))


@pytest.mark.parametrize(
    "metric,warn,critical",
    [
        ("queue_depth", 128, 224),
        ("oldest_pending_age_seconds", 300, 900),
        ("sqlite_database_bytes", 256 * 2**20, 512 * 2**20),
        ("sqlite_wal_bytes", 16 * 2**20, 64 * 2**20),
        ("rss_memory_mb", 512, 1024),
    ],
)
@pytest.mark.parametrize(
    "position,expected", [("below", "NORMAL"), ("warn", "WARNING"), ("critical", "CRITICAL")]
)
def test_threshold_boundaries(tmp_path, metric, warn, critical, position, expected):
    p, _, _ = configured(tmp_path)
    value = warn - 1 if position == "below" else warn if position == "warn" else critical
    with patch.object(module, "measure_capacity", return_value=complete_metrics(**{metric: value})):
        assert capacity_observation(p).status == expected


@pytest.mark.parametrize(
    "free,status",
    [(512 * 2**20 + 1, "NORMAL"), (512 * 2**20, "WARNING"), (128 * 2**20, "CRITICAL")],
)
def test_low_disk_boundaries(tmp_path, free, status):
    p, _, _ = configured(tmp_path)
    with patch.object(
        module, "measure_capacity", return_value=complete_metrics(available_disk_bytes=free)
    ):
        assert capacity_observation(p).status == status


def test_unknown_measurements_never_normal(tmp_path):
    p, _, _ = configured(tmp_path)
    with patch.object(module, "measure_capacity", return_value=CapacityMetrics()):
        assert capacity_observation(p).status == "UNKNOWN"
    with patch.object(
        p.queue.database, "_connect", side_effect=sqlite3.OperationalError("read failure")
    ):
        result = capacity_observation(p)
    assert result.metrics.queue_depth is None and result.status == "UNKNOWN"
    with patch.object(module.shutil, "disk_usage", side_effect=OSError("disk unreadable")):
        assert capacity_observation(p).metrics.available_disk_bytes is None


def test_queue_growth_observed_and_wal_physical_size(tmp_path):
    p, _, _ = configured(tmp_path)
    previous = capacity_observation(p)
    p.queue.enqueue(project_journal(row(2, 30)))
    current = capacity_observation(p, previous=previous)
    assert any(
        f.metric == "queue_depth" and f.reason == "INCREASED" and f.delta == 1
        for f in current.findings
    )
    # Separate test SQLite WAL: only this private connection and database, not production mode.
    conn = sqlite3.connect(p.queue.database.path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE fixture_wal(x)")
    conn.execute("INSERT INTO fixture_wal VALUES(1)")
    conn.commit()
    try:
        expected = Path(str(p.queue.database.path) + "-wal").stat().st_size
        assert expected > 0 and measure_capacity(p).sqlite_wal_bytes == expected
    finally:
        conn.close()


def test_capacity_log_failure_and_binding_do_not_change_events(tmp_path):
    p, _, _ = configured(tmp_path)
    log = MaintenanceLog.create(p.queue.database.path.parent / "maintenance.sqlite", p)
    observation = capacity_observation(p)
    record_capacity(log, observation)
    assert log.entries()[-1]["operation"] == "CAPACITY_OBSERVATION"
    before = p.queue.counts()
    with patch.object(log.database, "_commit", side_effect=sqlite3.OperationalError("disk full")):
        with pytest.raises(StorageError):
            record_capacity(log, observation)
    assert p.queue.counts() == before
    forged = observation.model_copy(update={"binding_digest": "0" * 64})
    with pytest.raises(ValueError):
        record_capacity(log, forged)
    assert asyncio.run(security_check(p))["write_spy_calls"] == 0


def test_queue_commit_fail_cursor_unchanged_and_not_done(tmp_path):
    p, event, _ = configured(tmp_path)
    old = p.queue.cursor(p.binding["collector"])
    with patch.object(p.queue.database, "_commit", side_effect=sqlite3.OperationalError("full")):
        with pytest.raises(StorageError):
            p.queue.enqueue(project_journal(row(2, 30)), cursor_source=p.binding["collector"])
    assert p.queue.cursor(p.binding["collector"]) == old
    assert p.queue.counts() == {"DONE": 1}


def test_example_threshold_order_and_nonfinite_rejected():
    with pytest.raises(ValueError):
        ExampleThresholds(queue_warning=225, queue_critical=224)
    with pytest.raises(ValueError):
        CapacityMetrics(rss_memory_mb=float("nan"))


def test_rehashed_false_normal_unknown_is_rejected(tmp_path):
    from soc_agent.security_ai.external.models import content_digest_payload

    p, _, _ = configured(tmp_path)
    with patch.object(module, "measure_capacity", return_value=CapacityMetrics()):
        data = capacity_observation(p).model_dump(mode="json")
    data["status"] = "NORMAL"
    data["observation_digest"] = content_digest_payload(
        {k: v for k, v in data.items() if k not in ("measured_at", "observation_digest")}
    )
    with pytest.raises(ValueError):
        CapacityObservation.model_validate(data)


@pytest.mark.parametrize("receipt", [[], {}])
def test_malformed_receipt_metrics_unknown(tmp_path, receipt):
    p, _, _ = configured(tmp_path)
    with p.queue.database.transaction() as c:
        c.execute(
            "UPDATE realtime_events SET outcome=?",
            (json.dumps({"workflow": {"receipt": receipt}}),),
        )
    metrics = measure_capacity(p)
    assert metrics.queue_depth is None and metrics.provenance_record_count is None
