"""Preparation failures use temporary stores and never start a privileged helper."""

import json
from unittest.mock import AsyncMock, Mock

import pytest

from soc_agent.review.persistence.models import StorageError
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture import calibrated_session
from soc_agent.security_ai.operational.network_capture.calibrated_policy import policy
from soc_agent.security_ai.research import stream_service
from soc_agent.security_ai.research.stream_service import StreamingMonitoring, preparation_error


@pytest.fixture(autouse=True)
def no_models_or_headroom_dependency(monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
        lambda: dict(affinity_cpus=4, available_memory_bytes=8 * 1024**3),
    )
    monkeypatch.setattr(
        "soc_agent.security_ai.research.adapter.ResearchAdapter.status",
        lambda *args: {"status": "READY"},
    )


@pytest.mark.asyncio
async def test_archive_gate_reports_original_code_without_touching_retained_store(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True)
    owner.root.mkdir(mode=0o700)
    for i in range(8):
        (owner.root / f"session-{i}").mkdir(mode=0o700)
    previous_store, previous_demo = Mock(), Mock(stop=AsyncMock())
    owner.store, owner.demo = previous_store, previous_demo
    owner.fixture = True
    owner.flow_count = owner.eligible = owner.excluded = 7
    result = await owner.start(policy=policy("balanced-v2"))
    assert result == {
        "status": "BLOCKED",
        "last_error": "STREAM_ARCHIVAL_REQUIRED",
        "listener_ready": False,
        "preparation_phase": "SESSION_ARCHIVE",
        "preparation_audit": "NOT_AVAILABLE_BEFORE_SESSION_STORE",
    }
    assert owner.session is owner.store is owner.capture is None
    assert len(list(owner.root.glob("session-*"))) == 8
    assert not owner.preparing and owner.last_error == "STREAM_ARCHIVAL_REQUIRED"
    previous_store.runtime.event.assert_not_called()
    previous_demo.stop.assert_not_awaited()
    assert not owner.snapshot()["listener_ready"]
    assert owner.snapshot()["input_origin"] == "NO_DATA"
    assert owner.flow_count == owner.eligible == owner.excluded == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["headroom", "bundle", "storage", "model"])
async def test_failure_categories_are_bounded_and_no_command_is_available(
    tmp_path, monkeypatch, caplog, failure
):
    owner = StreamingMonitoring(tmp_path, total=True)
    if failure == "headroom":
        monkeypatch.setattr(
            "soc_agent.security_ai.operational.network_capture.calibrated_policy.hardware",
            lambda: dict(affinity_cpus=1, available_memory_bytes=1024),
        )
        expected = "CALIBRATED_RESOURCE_HEADROOM_REQUIRED"
    elif failure == "bundle":

        def invalid_bundle():
            raise ValueError("CALIBRATED_HELPER_BUNDLE_MISMATCH")

        monkeypatch.setattr(calibrated_session, "verify_bundle", invalid_bundle)
        expected = "CALIBRATED_HELPER_BUNDLE_MISMATCH"
    elif failure == "storage":

        def invalid_storage(*args, **kwargs):
            raise OSError("private/path/sensitive")

        monkeypatch.setattr(stream_service, "StreamStore", invalid_storage)
        expected = "STREAM_SESSION_STORAGE_FAILED"
    else:
        monkeypatch.setattr(
            "soc_agent.security_ai.research.adapter.ResearchAdapter.status",
            lambda *args: {"status": "BLOCKED", "error": "private/path/sensitive"},
        )
        expected = "STREAM_ARTIFACT_ENVIRONMENT_BLOCKED"
    result = await owner.start(policy=policy("balanced-v2"))
    assert result["last_error"] == expected and result["listener_ready"] is False
    assert "command" not in result and "helper_sha256" not in result
    assert not owner.preparing and owner.state == "ERROR"
    assert "private/path/sensitive" not in caplog.text
    assert not owner.snapshot()["collection_live"]
    assert owner.command("invalid")["status"] == "BLOCKED"
    if failure == "model":
        assert result["preparation_audit"] == "RECORDED"
        owner.store.runtime.verify_audit()
        with owner.store.runtime.database.transaction(write=False) as c:
            rows = c.execute(
                "SELECT payload FROM monitor_audit WHERE "
                "json_extract(payload,'$.kind')='STREAM_PREPARATION_FAILED'"
            ).fetchall()
        assert len(rows) == 1
        assert json.loads(rows[0][0])["details"] == {"code": expected, "phase": "MODEL_ENVIRONMENT"}
    else:
        assert result["preparation_audit"] == "NOT_AVAILABLE_BEFORE_SESSION_STORE"


@pytest.mark.asyncio
async def test_real_nonblocking_lock_conflict_is_not_reported_as_environment_failure(
    tmp_path, monkeypatch
):
    held = tmp_path / "held.lock"
    held.touch(mode=0o600)
    owner = StreamingMonitoring(tmp_path, total=True)
    monkeypatch.setattr(
        stream_service, "exclusive_runtime_lock", lambda _: exclusive_runtime_lock(held)
    )
    with exclusive_runtime_lock(held):
        result = await owner.start(policy=policy("balanced-v2"))
        assert result["last_error"] == "STREAM_RUNTIME_LOCK_CONFLICT"
        assert result["preparation_phase"] == "RUNTIME_LOCK"
        assert result["preparation_audit"] == "NOT_AVAILABLE_BEFORE_SESSION_STORE"
        assert owner.writer_lock is None
        with pytest.raises(BlockingIOError):
            with exclusive_runtime_lock(held):
                pytest.fail("The foreign lock must stay held")
    assert not owner.capture and not owner.snapshot()["listener_ready"]


@pytest.mark.asyncio
async def test_audit_failure_remains_blocked_without_leaking_exception(
    tmp_path, monkeypatch, caplog
):
    from soc_agent.linux_runtime.store import RuntimeStore

    original = RuntimeStore.event

    def failing(self, kind, details):
        if kind == "STREAM_PREPARATION_FAILED":
            raise StorageError("private/path/sensitive")
        return original(self, kind, details)

    monkeypatch.setattr(RuntimeStore, "event", failing)
    monkeypatch.setattr(
        "soc_agent.security_ai.research.adapter.ResearchAdapter.status",
        lambda *args: {"status": "BLOCKED"},
    )
    owner = StreamingMonitoring(tmp_path, total=True)
    result = await owner.start(policy=policy("balanced-v2"))
    assert result["last_error"] == "STREAM_SESSION_STORAGE_FAILED"
    assert result["preparation_audit"] == "FAILED" and not result["listener_ready"]
    assert "private/path/sensitive" not in caplog.text
    assert owner.writer_lock is None


@pytest.mark.asyncio
async def test_unknown_preparation_exception_is_not_exposed(tmp_path, monkeypatch, caplog):
    owner = StreamingMonitoring(tmp_path, total=True)

    async def unknown(*args, **kwargs):
        raise ValueError("private/path/sensitive")

    monkeypatch.setattr(owner, "_prepare", unknown)
    result = await owner.start(policy=policy("balanced-v2"))
    assert result["last_error"] == "STREAM_PREPARE_FAILED"
    assert "private/path/sensitive" not in caplog.text
    assert (
        preparation_error(ValueError("CALIBRATED_UNREVIEWED_SECRET"), "UNKNOWN")
        == "STREAM_PREPARE_FAILED"
    )


@pytest.mark.asyncio
async def test_ready_stop_restart_use_new_identity_without_capture_or_authentication(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True)
    first = await owner.start(policy=policy("balanced-v2"))
    try:
        assert first["listener_ready"] is True and owner.capture.listener_ready()
        assert owner.snapshot()["collection_live"] is False
        identity = first["session_id"]
        await owner.stop()
        assert not owner.capture.listener_ready()
        assert owner.command(identity)["status"] == "BLOCKED"
        second = await owner.start(policy=policy("balanced-v2"))
        assert second["listener_ready"] is True and second["session_id"] != identity
        assert owner.command(identity)["status"] == "BLOCKED"
    finally:
        await owner.stop()
