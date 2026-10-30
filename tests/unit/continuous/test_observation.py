"""Health mirrors are atomic views, never approval or authoritative event stores."""

import json
import sqlite3
import time
from unittest.mock import Mock

import pytest
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.cli import observed_status
from soc_agent.continuous.store import Store


def snapshot(**updates):
    return (
        dict(
            state="RUNNING",
            source="JSONL_REPLAY",
            collector="RUNNING_REPLAY",
            worker="IDLE",
            heartbeat_unix=time.time(),
            queue={"PENDING": 2},
            collection_live=False,
            cleanup="PENDING_SERVICE_STOP",
        )
        | updates
    )


def test_observer_reads_committed_view_while_writer_is_locked(tmp_path, monkeypatch):
    directory, store = make(tmp_path)
    store.update(snapshot())
    with sqlite3.connect(directory / "service.sqlite") as held:
        held.execute("BEGIN EXCLUSIVE")
        # No connection to SQLite is allowed in the fast display/health reader.
        monkeypatch.setattr(sqlite3, "connect", Mock(side_effect=AssertionError("DB read")))
        shown = observed_status(directory)
    assert shown["state"] == "RUNNING" and shown["queue"] == {"PENDING": 2}
    assert not shown["collection_live"]


def test_failed_atomic_publication_keeps_complete_previous_view(tmp_path, monkeypatch):
    directory, store = make(tmp_path)
    store.update(snapshot())
    previous = (directory / "observation.json").read_bytes()

    def fail(*args):
        raise OSError("INJECTED_PUBLISH_FAILURE")

    monkeypatch.setattr("soc_agent.continuous.store.os.replace", fail)
    with pytest.raises(OSError, match="PUBLISH_FAILURE"):
        store.update(snapshot(worker="CHANGED"))
    assert (directory / "observation.json").read_bytes() == previous
    assert not list(directory.glob(".observation-*"))
    assert observed_status(directory)["worker"] == "IDLE"
    assert store.state()["worker"] == "CHANGED"  # DB remains the authority.


def test_mirror_digest_and_source_changes_fail_closed(tmp_path):
    directory, store = make(tmp_path)
    store.update(snapshot())
    path = directory / "observation.json"
    body = json.loads(path.read_text())
    body["snapshot"]["collection_live"] = True
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="OBSERVATION_INTEGRITY"):
        observed_status(directory)
    store.update(snapshot(source="NATIVE_SERVICE"))
    with pytest.raises(ValueError, match="OBSERVATION_SOURCE"):
        observed_status(directory)


def test_stale_mirror_never_claims_live_capture(tmp_path):
    directory, store = make(tmp_path)
    store.update(snapshot(heartbeat_unix=0, collection_live=True))
    shown = observed_status(directory)
    assert shown["state"] == "UNKNOWN_STALE_HEARTBEAT"
    assert shown["collection_live"] is False and shown["cleanup"].startswith("UNVERIFIED")


def test_old_runtime_without_mirror_and_current_stop_view(tmp_path):
    directory, store = make(tmp_path)
    assert observed_status(directory)["state"] == "STOPPED"
    store.update(snapshot(state="STOPPED", cleanup="VERIFIED", queue={"POISON": 1}))
    shown = observed_status(directory)
    assert shown["cleanup"] == "VERIFIED" and shown["queue"] == {"POISON": 1}
    assert (directory / "observation.json").stat().st_mode & 0o777 == 0o600
    assert Store(directory).state()["state"] == "STOPPED"


def test_large_report_remains_in_store_not_health_mirror(tmp_path):
    directory, store = make(tmp_path)
    detail = "e" * 300000
    store.update(
        snapshot(
            analysis=dict(output="/verified/output", result=dict(inference_count=2, detail=detail))
        )
    )
    assert store.state()["analysis"]["result"]["detail"] == detail
    shown = observed_status(directory)
    assert shown["analysis"]["result"]["inference_count"] == 2
    assert "detail" not in shown["analysis"]["result"]
    assert shown["analysis"]["result"]["detail_reference"].startswith("OPEN_VERIFIED")
    assert (directory / "observation.json").stat().st_size < 262144


def test_mirror_does_not_grant_native_start(tmp_path, monkeypatch):
    import asyncio

    from soc_agent.continuous.models import ContinuousConfig
    from soc_agent.gui.backend import Backend, GUIConfig

    directory, store = make(tmp_path)
    cfg = store.config.model_copy(update={"source": "NATIVE_SERVICE"})
    native = tmp_path / "native"
    Store.create(native, ContinuousConfig.model_validate(cfg))
    forbidden = Mock(side_effect=AssertionError("unapproved process"))
    monkeypatch.setattr("soc_agent.continuous.cli.start", forbidden)
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui", continuous_directory=native))
    with pytest.raises(ValueError, match="APPROVED_SERVICE_ENTRYPOINT"):
        asyncio.run(backend.continuous_start())
    forbidden.assert_not_called()


@pytest.mark.parametrize("malformed", [False, True])
def test_explicit_controller_error_preserved_without_fake_live_state(tmp_path, malformed):
    import asyncio

    from soc_agent.gui.backend import Backend, GUIConfig

    directory, store = make(tmp_path)
    store.update(snapshot(state="STOPPED", cleanup="VERIFIED"))
    evidence = tmp_path / "execution"
    evidence.mkdir(mode=0o700)
    path = evidence / "first-error.json"
    path.write_text(
        json.dumps(
            []
            if malformed
            else dict(
                stage="CAPTURE",
                error="OperationalError",
                message="database is locked",
                unselected="excluded",
            )
        )
    )
    path.chmod(0o600)
    backend = Backend(
        GUIConfig(
            data_directory=tmp_path / "gui",
            continuous_directory=directory,
            continuous_execution_evidence=evidence,
        )
    )
    shown = asyncio.run(backend.production_status())
    assert shown["state"] == "STOPPED" and not shown["collection_live"]
    assert shown["last_error"] == "CONTINUOUS_CONTROLLER_FAILURE"
    error = shown["continuous"]["controller_error"]
    if malformed:
        assert error == {"error": "CONTROLLER_DIAGNOSTIC_UNVERIFIED"}
    else:
        assert error["stage"] == "CAPTURE" and error["message"] == "database is locked"
        assert "unselected" not in error


def test_final_degraded_stop_keeps_failure_instead_of_claiming_lost_running_service(tmp_path):
    directory, store = make(tmp_path)
    store.update(
        snapshot(
            state="DEGRADED",
            heartbeat_unix=0,
            collector="STOPPED",
            worker="STOPPED",
            final_flush="VERIFIED",
            cleanup="UNVERIFIED",
            last_error="CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE",
        )
    )
    before = (directory / "observation.json").read_bytes()
    shown = observed_status(directory)
    assert shown["heartbeat_stale"] and shown["state"] == "DEGRADED"
    assert shown["collector"] == shown["worker"] == "STOPPED"
    assert not shown["collection_live"] and shown["cleanup"] == "UNVERIFIED"
    assert shown["last_error"] == "CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE"
    assert (directory / "observation.json").read_bytes() == before
