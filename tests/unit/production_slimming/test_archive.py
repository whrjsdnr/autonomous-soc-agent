"""Atomic preservation and fail-closed recovery, using private fixture sessions only."""

import json
from uuid import uuid4

import pytest

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.research.session_archive import Archive, _write, inspect


def session(root):
    create_private_directory(root)
    path = root / ("session-" + uuid4().hex)
    create_private_directory(path)
    identity = path / "session.json"
    identity.write_text(json.dumps({"session_id": str(uuid4()), "digest": "FIXTURE_ONLY"}))
    identity.chmod(0o600)
    create_private_directory(path / "runtime")
    store = RuntimeStore.create(
        path / "runtime",
        RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3),
    )
    store.event(
        "STREAM_STARTED",
        {"session_digest": content_digest_payload(json.loads(identity.read_text()))},
    )
    store.event("STREAM_ABORTED", {"error": "FIXTURE_FAILURE"})
    create_private_file(path / "runtime/writer.lock")
    return path


def test_archive_eight_sessions_releases_active_budget_without_deleting_evidence(tmp_path):
    root = tmp_path / "total-monitoring"
    paths = [session(root) for _ in range(8)]
    before = {p.name: inspect(p) for p in paths}
    archive = Archive(root)
    result = archive.archive_inactive()
    assert result["active"] == 0 and len(result["archived"]) == 8
    for name, evidence in before.items():
        assert archive.verify(name) == evidence
        assert evidence["capture_validation"] == "PRESERVED_NOT_PROMOTED"
    assert archive.archive_inactive() == result
    assert session(root).exists()  # New identity, not reuse.


def test_active_lock_blocks_all_transitions(tmp_path):
    root = tmp_path / "total-monitoring"
    first, active = session(root), session(root)
    with exclusive_runtime_lock(active / "runtime/writer.lock"):
        with pytest.raises(BlockingIOError):
            Archive(root).archive_inactive()
    assert first.exists() and active.exists()


@pytest.mark.parametrize("fault", ["audit", "symlink", "wal", "socket"])
def test_bad_evidence_cannot_be_archived(tmp_path, fault):
    import socket
    import sqlite3

    root = tmp_path / "total-monitoring"
    path = session(root)
    channel = None
    if fault == "audit":
        with sqlite3.connect(path / "runtime/monitor.sqlite") as db:
            db.execute("UPDATE monitor_audit SET digest='bad' WHERE sequence=1")
    elif fault == "symlink":
        (path / "link").symlink_to(path / "session.json")
    elif fault == "wal":
        create_private_file(path / "runtime/monitor.sqlite-wal")
    else:
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.bind(str(tmp_path / "s"))
        (tmp_path / "s").rename(path / "socket")
    try:
        with pytest.raises(ValueError):
            Archive(root).archive_inactive()
        assert path.exists()
    finally:
        if channel:
            channel.close()


@pytest.mark.parametrize("moved", [False, True])
def test_crash_recovery_before_and_after_atomic_move(tmp_path, moved):
    root = tmp_path / "total-monitoring"
    path = session(root)
    archive = Archive(root)
    archive._setup()
    value = inspect(path)
    pending = archive.directory / (".pending-" + path.name + ".json")
    _write(pending, {**value, "manifest_digest": content_digest_payload(value)})
    if moved:
        path.rename(archive.directory / path.name)
    archive.archive_inactive()
    assert not pending.exists()
    assert archive.verify(path.name) == value


def test_tampering_and_capacity_are_not_silently_accepted(tmp_path, monkeypatch):
    root = tmp_path / "total-monitoring"
    path = session(root)
    monkeypatch.setattr("soc_agent.security_ai.research.session_archive.MAX_ARCHIVES", 0)
    with pytest.raises(ValueError, match="CAPACITY"):
        Archive(root).archive_inactive()
    assert path.exists()
    monkeypatch.setattr("soc_agent.security_ai.research.session_archive.MAX_ARCHIVES", 64)
    archive = Archive(root)
    archive.archive_inactive()
    (archive.directory / path.name / "session.json").write_text("{}")
    with pytest.raises(ValueError):
        archive.status()


def test_existing_empty_readable_lock_is_preserved_without_chmod(tmp_path):
    root = tmp_path / "total-monitoring"
    path = session(root)
    lock = path / "runtime/writer.lock"
    lock.chmod(0o644)
    archive = Archive(root)
    archive.archive_inactive()
    archived_lock = archive.directory / path.name / "runtime/writer.lock"
    assert archived_lock.stat().st_mode & 0o777 == 0o644
    assert archived_lock.read_bytes() == b""


def test_nonempty_or_writable_coordination_file_is_rejected(tmp_path):
    root = tmp_path / "total-monitoring"
    path = session(root)
    lock = path / "runtime/writer.lock"
    lock.write_text("not a sentinel")
    with pytest.raises(ValueError, match="UNSAFE_LOCK"):
        Archive(root).archive_inactive()
    assert path.exists()


@pytest.mark.asyncio
async def test_corrupt_archive_blocks_new_preparation_before_model_or_capture(tmp_path):
    from soc_agent.security_ai.research.stream_service import StreamingMonitoring

    owner = StreamingMonitoring(tmp_path, total=True)
    path = session(owner.root)
    archive = Archive(owner.root)
    archive.archive_inactive()
    (archive.directory / (path.name + ".json")).write_text("{}")
    reply = await owner.start()
    assert reply["last_error"] == "STREAM_ARCHIVE_INTEGRITY_BLOCKED"
    assert not reply["listener_ready"]
    assert owner.capture is None and owner.demo is None


def test_session_identity_cannot_be_swapped_under_a_valid_audit(tmp_path):
    root = tmp_path / "total-monitoring"
    path = session(root)
    identity = json.loads((path / "session.json").read_text())
    identity["session_id"] = str(uuid4())
    (path / "session.json").write_text(json.dumps(identity))
    with pytest.raises(ValueError, match="SESSION_AUDIT_MISMATCH"):
        Archive(root).archive_inactive()
    assert path.exists()
