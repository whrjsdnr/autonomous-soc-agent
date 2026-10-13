from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.authentication.aggregation import AuthenticationEvent
from soc_agent.security_ai.operational.source_records import AuthenticationSource, SourceHeader
from soc_agent.security_ai.operational.source_store import OperationalSourceStore, SourceRejected

TIME = datetime(2026, 1, 1, tzinfo=UTC)
INCIDENT = UUID(int=19)


def source(number=1, seconds=0, result="failure", incident=INCIDENT):
    when = TIME + timedelta(seconds=seconds)
    identity = str(number)
    return AuthenticationSource(
        header=SourceHeader(
            incident_id=incident,
            event_id=identity,
            source=SourceIdentity(namespace="declared-auth", generation="host-1", record=identity),
            collector_id="structured-auth",
            collector_version="1.0",
            observed_at=when,
        ),
        event=AuthenticationEvent(
            event_id=identity,
            event_time=when,
            account_id="test-account",
            source_identifier="test-origin",
            authentication_result=result,
        ),
    )


def store(tmp_path, **kwargs):
    return OperationalSourceStore.create(
        tmp_path / "private" / "sources.sqlite",
        allowed_lateness_seconds=60,
        max_future_skew_seconds=5,
        **kwargs,
    )


def admit(s, event):
    return s.ingest(
        event,
        expected_incident=INCIDENT,
        expected_source_digest=event.content_digest,
        received_at=TIME + timedelta(seconds=1000),
    )


def test_auth_success_failure_window_duplicate_restart(tmp_path):
    s = store(tmp_path)
    assert admit(s, source()).status == "ACCEPTED"
    assert admit(s, source(2, 30, "success")).status == "ACCEPTED"
    snapshot = s.windows(INCIDENT)
    assert len(snapshot) == 1
    assert snapshot[0].window.features.input_payload()["failure_rate"] == 0.5
    assert snapshot[0].window.features.input_payload()["login_attempt_rate"] == 2 / 300
    assert len(snapshot[0].source_digests) == 2
    assert admit(s, source()).duplicate
    s = OperationalSourceStore(
        s.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    assert s.windows(INCIDENT) == snapshot


def test_half_open_boundaries_and_lateness(tmp_path):
    s = store(tmp_path)
    admit(s, source(1, 299))
    admit(s, source(2, 300))
    assert len(s.windows(INCIDENT)) == 2
    assert admit(s, source(3, 240)).status == "ACCEPTED"  # exactly watermark included
    assert admit(s, source(4, 239)).status == "LATE_QUARANTINED"
    assert admit(s, source(4, 239)).duplicate
    windows = s.windows(INCIDENT)
    assert sum(w.window.features.input_payload()["total_login_count"] for w in windows) == 3
    reopened = OperationalSourceStore(
        s.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    assert reopened.windows(INCIDENT) == windows


def test_conflicting_source_identity_and_incident(tmp_path):
    s = store(tmp_path)
    a = source()
    admit(s, a)
    with pytest.raises(SourceRejected, match="INCIDENT_MISMATCH"):
        admit(s, source(2, incident=UUID(int=20)))
    changed = source(result="success")
    with pytest.raises(SourceRejected, match="IDENTITY_CONFLICT"):
        admit(s, changed)
    with pytest.raises(SourceRejected, match="DIGEST_MISMATCH"):
        s.ingest(
            source(3), expected_incident=INCIDENT, expected_source_digest="0" * 64, received_at=TIME
        )


def test_source_timestamp_and_future_rejected(tmp_path):
    s = store(tmp_path)
    with pytest.raises(SourceRejected, match="FUTURE"):
        s.ingest(
            source(seconds=6),
            expected_incident=INCIDENT,
            expected_source_digest=source(seconds=6).content_digest,
            received_at=TIME,
        )
    with pytest.raises(ValueError):
        SourceHeader.model_validate(
            source().header.model_dump() | {"observed_at": datetime(2026, 1, 1)}
        )
    with pytest.raises(ValueError):
        AuthenticationSource.model_validate(
            source().model_dump() | {"event": source(seconds=1).event.model_dump()}
        )


def test_corrupted_source_and_watermark_fail_closed(tmp_path):
    s = store(tmp_path)
    admit(s, source())
    with s.database.transaction() as c:
        c.execute("UPDATE operational_watermarks SET digest=?", ("0" * 64,))
    with pytest.raises(SourceRejected, match="WATERMARK"):
        s.windows(INCIDENT)


def test_atomic_admission_snapshot_rollback(tmp_path, monkeypatch):
    s = store(tmp_path)

    def failed(*_):
        raise RuntimeError("injected snapshot failure")

    monkeypatch.setattr(s, "_snapshot", failed)
    with pytest.raises(RuntimeError):
        admit(s, source())
    reopened = OperationalSourceStore(
        s.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    assert not reopened.windows(INCIDENT)
    with reopened.database.transaction(write=False) as c:
        assert c.execute("SELECT count(*) FROM operational_sources").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM operational_watermarks").fetchone()[0] == 0


def test_capacity_and_policy_reopen(tmp_path):
    s = store(tmp_path, capacity=1)
    admit(s, source())
    with pytest.raises(SourceRejected, match="CAPACITY"):
        admit(s, source(2))
    with pytest.raises(SourceRejected, match="CONFIG"):
        OperationalSourceStore(
            s.database.path, allowed_lateness_seconds=61, max_future_skew_seconds=5, capacity=1
        )
    with pytest.raises(SourceRejected, match="EXISTING_DATABASE"):
        OperationalSourceStore.create(
            s.database.path, allowed_lateness_seconds=60, max_future_skew_seconds=5
        )
