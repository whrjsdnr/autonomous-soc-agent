import asyncio
import json
import os
from uuid import uuid4

import pytest

from soc_agent.security_ai.collectors.handoff import exchange, read_controller
from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_contract import LivePlan
from soc_agent.security_ai.collectors.live_process import main


async def prepared(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", lambda _: {}
    )
    c = LiveZeekCollector(tmp_path)
    await c.prepare()
    await c.start()
    return c


@pytest.mark.asyncio
async def test_ready_probe_claim_validate_and_no_second_launcher(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    try:
        snap = c.snapshot()
        assert snap["handoff_listener_ready"] and snap["controller_alive"] and snap["command_valid"]
        value = await c.command_snapshot(
            snap["session_id"], snap["plan_digest"], snap["controller_generation"]
        )
        assert value["collector_command"]
        await asyncio.to_thread(exchange, c.directory, c.plan, "claim")
        assert c.snapshot()["state"] == "LAUNCHER_STARTING"
        assert not c.snapshot()["command_valid"] and c.snapshot()["collector_command"] is None
        await asyncio.to_thread(exchange, c.directory, c.plan, "validate")
        with pytest.raises(ValueError, match="REUSE_DENIED"):
            await asyncio.to_thread(exchange, c.directory, c.plan, "claim")
        assert c.handoff.accepted["pid"] == os.getpid()
        c.store.verify()
    finally:
        await c.stop()


@pytest.mark.asyncio
async def test_approval_wait_beyond_old_deadline_does_not_stop(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    try:
        c.watch_started -= 86400
        await asyncio.sleep(0.15)
        assert c.snapshot()["command_valid"] and not (c.directory / "stop.request").exists()
        assert c.state == "AUTHENTICATION_REQUIRED"
    finally:
        await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["start_ticks", "session_id", "plan_digest", "generation", "pid"])
async def test_identity_tampering_fails_closed(tmp_path, monkeypatch, field):
    c = await prepared(tmp_path, monkeypatch)
    path = c.directory / "controller.json"
    raw = json.loads(path.read_text())
    raw[field] = (
        "0"
        if field == "start_ticks"
        else "0" * 64
        if field == "plan_digest"
        else 2147483647
        if field == "pid"
        else str(uuid4())
    )
    path.write_text(json.dumps(raw))
    try:
        with pytest.raises(ValueError, match="CONTROLLER_(IDENTITY_MISMATCH|NOT_RUNNING)"):
            read_controller(c.directory, c.plan)
        with pytest.raises(ValueError):
            await c.command_snapshot(
                str(c.plan.session_id), c.plan.identity, str(c.plan.controller_generation)
            )
    finally:
        await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason", ["USER_STOP", "GUI_CLOSE", "CONTROLLER_EXIT", "PREPARATION_CANCELLED"]
)
async def test_explicit_stop_is_typed_audited_and_idempotent(tmp_path, monkeypatch, reason):
    c = await prepared(tmp_path, monkeypatch)
    await c.stop(reason)
    raw = (c.directory / "stop.request").read_bytes()
    stop = json.loads(raw)
    assert stop["reason"] == reason and stop["plan_digest"] == c.plan.identity
    assert stop["generation"] == str(c.plan.controller_generation)
    assert not c.snapshot()["handoff_listener_ready"] and not c.snapshot()["command_valid"]
    assert c.state == "STOPPED"
    await c.stop("USER_STOP")
    assert (c.directory / "stop.request").read_bytes() == raw
    with c.store.runtime.database.transaction(write=False) as db:
        kinds = [json.loads(r[0])["kind"] for r in db.execute("SELECT payload FROM monitor_audit")]
    assert kinds.count("COLLECTOR_STOP_REQUESTED") == 1 and kinds.count("CONTROLLER_EXITED") == 1
    assert "TERMINAL_HANDOFF_READY" in kinds
    c.store.verify()
    with pytest.raises(ValueError, match="SESSION_STOP_REQUESTED"):
        await asyncio.to_thread(main, ["--session", str(c.directory), "--approve", c.plan.identity])


@pytest.mark.asyncio
async def test_restart_generation_and_old_command_rejected(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    snap = c.snapshot()
    await c.stop()
    await c.prepare()
    await c.start()
    try:
        assert c.started is None
        assert c.snapshot()["controller_generation"] != snap["controller_generation"]
        with pytest.raises(ValueError, match="IDENTITY_MISMATCH"):
            await c.command_snapshot(
                snap["session_id"], snap["plan_digest"], snap["controller_generation"]
            )
        assert c.snapshot()["command_valid"]
    finally:
        await c.close()


@pytest.mark.asyncio
async def test_unexpected_listener_close_is_error_not_ready(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    await c.handoff.close()
    await asyncio.wait_for(c.task, 3)
    assert c.state == "ERROR" and c.last_error == "ZEEK_LISTENER_UNAVAILABLE"
    assert not c.snapshot()["command_valid"]
    assert json.loads((c.directory / "stop.request").read_text())["reason"] == "LAUNCH_FAILED"
    await c.stop()


@pytest.mark.asyncio
async def test_wrong_approval_no_auth_and_sidecar_only_safe_code(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)

    def forbidden():
        raise AssertionError("AUTHENTICATION MUST NOT RUN")

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", forbidden)
    with pytest.raises(ValueError, match="APPROVAL_DIGEST_MISMATCH"):
        await asyncio.to_thread(
            main, ["--session", str(c.directory), "--approve", "bad-private-value"]
        )
    await asyncio.wait_for(c.task, 3)
    assert c.last_error == "ZEEK_APPROVAL_DIGEST_MISMATCH"
    body = (c.directory / "launch-failure.json").read_text()
    assert "bad-private-value" not in body and "APPROVAL_DIGEST_MISMATCH" in body
    await c.stop()


@pytest.mark.asyncio
async def test_new_plan_rejects_legacy_contract_without_upgrade(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    raw = c.plan.model_dump(mode="json")
    raw["contract"] = "soc-zeek-native-plan:v1"
    raw.pop("controller_generation")
    with pytest.raises(ValueError):
        LivePlan.model_validate(raw)
    await c.stop()


@pytest.mark.asyncio
async def test_docker_spawn_failure_does_not_expose_path_or_retry(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", lambda: None)
    calls = []

    def broken(*args, **kwargs):
        calls.append(1)
        raise OSError("/private/path/credential not for GUI")

    monkeypatch.setattr("subprocess.Popen", broken)
    with pytest.raises(ValueError, match="ZEEK_DOCKER_START_FAILED"):
        await asyncio.to_thread(main, ["--session", str(c.directory), "--approve", c.plan.identity])
    await asyncio.wait_for(c.task, 3)
    assert c.state == "ERROR" and c.last_error == "ZEEK_DOCKER_START_FAILED"
    assert calls == [1]
    assert "private" not in (c.directory / "launch-failure.json").read_text()
    assert (c.directory / "exit.json").exists()
    assert not c.snapshot()["command_valid"]
    await c.stop()


@pytest.mark.asyncio
async def test_gui_close_during_terminal_auth_denies_capture(tmp_path, monkeypatch):
    import threading

    c = await prepared(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()

    def authenticate():
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr("soc_agent.cli.terminal_authenticate", authenticate)

    def forbidden(*args, **kwargs):
        raise AssertionError("NO CAPTURE PROCESS AFTER GUI CLOSE")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    task = asyncio.create_task(
        asyncio.to_thread(main, ["--session", str(c.directory), "--approve", c.plan.identity])
    )
    assert await asyncio.to_thread(entered.wait, 3)
    await c.close("GUI_CLOSE")
    release.set()
    with pytest.raises(ValueError, match="SESSION_STOP_REQUESTED"):
        await task
    assert not (c.directory / "process.json").exists()
    assert json.loads((c.directory / "stop.request").read_text())["reason"] == "GUI_CLOSE"
    assert not c.snapshot()["command_valid"]


@pytest.mark.asyncio
async def test_idle_clients_do_not_block_close_and_are_bounded(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    clients = []
    for _ in range(4):
        _, writer = await asyncio.open_unix_connection("\0" + c.handoff.identity.address[1:])
        clients.append(writer)
    await asyncio.sleep(0.05)
    assert len(c.handoff.connections) <= 4
    await asyncio.wait_for(c.close("GUI_CLOSE"), 4)
    for w in clients:
        w.close()
        await w.wait_closed()
    assert not c.snapshot()["command_valid"]


@pytest.mark.asyncio
async def test_cancelled_session_recovery_no_listener_or_capture_restart(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    await c.close("GUI_CLOSE")
    fresh = LiveZeekCollector(tmp_path)
    snapshot = await fresh.recover()
    assert snapshot["state"] == "STOPPED"
    assert snapshot["network"]["recovery_state"] == "RESTORED_CANCELLED_NO_CAPTURE_OR_RESTART"
    assert snapshot["stop_reason"] == "GUI_CLOSE"
    assert not snapshot["command_valid"] and not snapshot["controller_alive"]
    assert fresh.task is None and fresh.process_runner is None
    # No fabricated receipt or synthetic recovery inference.
    assert snapshot["research"]["records"] == []


@pytest.mark.asyncio
async def test_failed_new_preparation_does_not_append_to_previous_evidence(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    await c.stop()
    directory = c.directory
    before = (directory / "monitor.sqlite").read_bytes()
    stop_before = (directory / "stop.request").read_bytes()

    def unavailable(_):
        raise ValueError("ZEEK_PINNED_IMAGE_NOT_INSTALLED")

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.offline.OfflineZeek.environment", unavailable
    )
    with pytest.raises(ValueError):
        await c.prepare()
    assert (directory / "monitor.sqlite").read_bytes() == before
    assert (directory / "stop.request").read_bytes() == stop_before
    assert not c.snapshot()["command_valid"]


@pytest.mark.asyncio
async def test_corrupt_audit_blocks_handoff_before_authentication(tmp_path, monkeypatch):
    c = await prepared(tmp_path, monkeypatch)
    with c.store.runtime.database.transaction() as db:
        db.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("0" * 64,))
    try:
        with pytest.raises(ValueError, match="AUDIT_PERSISTENCE_FAILED"):
            await asyncio.to_thread(exchange, c.directory, c.plan, "claim")
        await asyncio.wait_for(c.task, 3)
        assert c.state == "ERROR" and c.handoff.accepted is None
        assert not c.snapshot()["command_valid"]
        assert (c.directory / "stop.request").exists()
    finally:
        await c.stop()
