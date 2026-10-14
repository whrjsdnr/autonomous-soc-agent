"""Actual Linux Unix sockets/peer credentials, fixture source data, pure simulator only."""

import asyncio
import json
import os
import socket
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from tests.integration.response_simulation.test_runtime_simulation import prepared

from soc_agent.linux_runtime.operator import (
    LIMIT,
    OperatorRequest,
    OperatorServer,
    operator_request,
    view,
)
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.state.evidence import utc_now


@asynccontextmanager
async def endpoint(tmp_path, monkeypatch):
    root, monitor, record = await prepared(tmp_path, monkeypatch)
    server = OperatorServer(monitor, (os.geteuid(),))
    with exclusive_runtime_lock(root / "writer.lock"):
        await server.start()
        try:
            yield root, monitor, record, server
        finally:
            await server.close()


async def send(root, command, record=None, **kwargs):
    if record is not None:
        kwargs.setdefault("candidate_id", record.request.candidate_id)
        kwargs.setdefault("expected_digest", view(record)["record_digest"])
    return await operator_request(root, command, **kwargs)


@pytest.mark.asyncio
async def test_live_approve_simulate_and_restart(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, server):
        assert (root / "operator/review.sock").stat().st_mode & 0o777 == 0o600
        assert not (await send(root, "execute", record))["ok"]
        assert (await send(root, "pending"))["result"][0]["status"] == "PENDING_APPROVAL"
        approved = await send(root, "approve", record)
        assert approved["ok"]
        assert approved["result"]["record"]["actor_assurance"] == "OS_PEER_IDENTITY"
        assert (
            approved["result"]["record"]["approval"]["decision"]["decided_by"]
            == f"os-uid:{os.geteuid()}"
        )
        assert not (await send(root, "approve", record))["ok"]
        done = await operator_request(
            root,
            "execute",
            candidate_id=record.request.candidate_id,
            expected_digest=approved["result"]["record_digest"],
        )
        assert done["ok"] and done["result"]["status"] == "SIMULATED"
        assert done["result"]["record"]["real_os_handler_calls"] == 0
        assert not (
            await operator_request(
                root,
                "execute",
                candidate_id=record.request.candidate_id,
                expected_digest=done["result"]["record_digest"],
            )
        )["ok"]
        assert (await send(root, "audit"))["ok"]
        assert (await send(root, "feedback"))["result"]["ground_truth_generation"] == "DISABLED"
        assert monitor.store.verify_audit()
    assert not (root / "operator/review.sock").exists()
    restarted = LinuxMonitor(root)
    assert restarted.simulation.load(record.request.candidate_id).status == "SIMULATED"
    assert restarted.store.verify_audit()


@pytest.mark.asyncio
async def test_os_kernel_reject_decision_is_durable(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        rejected = await send(root, "reject", record)
        assert rejected["ok"] and rejected["result"]["status"] == "REJECTED"
        assert not (
            await operator_request(
                root,
                "execute",
                candidate_id=record.request.candidate_id,
                expected_digest=rejected["result"]["record_digest"],
            )
        )["ok"]
        assert monitor.simulation.load(record.request.candidate_id).real_os_handler_calls == 0


@pytest.mark.asyncio
async def test_replay_request_id_persists_after_socket_restart(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, server):
        identity = uuid4()
        assert (await send(root, "detail", record, request_id=identity))["ok"]
        assert not (await send(root, "detail", record, request_id=identity))["ok"]
        await server.close()
        restarted = OperatorServer(monitor, (os.geteuid(),))
        await restarted.start()
        try:
            assert not (await send(root, "detail", record, request_id=identity))["ok"]
        finally:
            await restarted.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack", ["actor", "stale", "challenge", "oversize", "malformed", "command"]
)
async def test_untrusted_wire_payload_denied(tmp_path, monkeypatch, attack):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
        hello = json.loads(await reader.readline())
        body = OperatorRequest(
            request_id=uuid4(),
            challenge=hello["challenge"],
            created_at=utc_now(),
            command="approve",
            candidate_id=record.request.candidate_id,
            expected_digest=view(record)["record_digest"],
        ).model_dump(mode="json")
        if attack == "actor":
            body["actor"] = "root"
        if attack == "stale":
            body["created_at"] = (utc_now() - timedelta(seconds=31)).isoformat()
        if attack == "challenge":
            body["challenge"] = str(uuid4())
        if attack == "command":
            body["command"] = "block_ip"
        payload = json.dumps(body).encode()
        if attack == "oversize":
            payload = b"x" * (LIMIT + 2)
        if attack == "malformed":
            payload = b"not JSON"
        writer.write(payload + b"\n")
        await writer.drain()
        assert not json.loads(await reader.readline())["ok"]
        writer.close()
        await writer.wait_closed()
        assert monitor.simulation.load(record.request.candidate_id).status == "PENDING_REVIEW"


@pytest.mark.asyncio
async def test_missing_credentials_and_unauthorized_peer_denied(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, server):
        import soc_agent.linux_runtime.operator as module

        monkeypatch.setattr(module, "peer_uid", lambda sock: os.geteuid() + 1)
        reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
        assert not json.loads(await reader.readline())["ok"]
        writer.close()
        await writer.wait_closed()
        assert monitor.simulation.load(record.request.candidate_id).status == "PENDING_REVIEW"
        assert monitor.store.verify_audit()


@pytest.mark.asyncio
async def test_multi_cli_review_race_has_one_decision(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        results = await asyncio.gather(send(root, "approve", record), send(root, "reject", record))
        assert sum(r["ok"] for r in results) == 1
        assert monitor.simulation.load(record.request.candidate_id).status in (
            "APPROVED",
            "REJECTED",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["expiry", "target", "evidence", "policy", "incident"])
async def test_review_and_dispatch_revalidate_binding(tmp_path, monkeypatch, change):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        if change == "expiry":
            monitor.simulation.clock = lambda: record.approval.expires_at
            assert (await send(root, "detail", record))["result"]["status"] == "EXPIRED"
            assert not (await send(root, "approve", record))["ok"]
            return
        approved = await send(root, "approve", record)
        assert approved["ok"]
        if change in ("target", "incident"):
            # JSON cannot carry a changed action/incident: strict extra-field denial.
            reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
            hello = json.loads(await reader.readline())
            body = OperatorRequest(
                request_id=uuid4(),
                challenge=hello["challenge"],
                created_at=utc_now(),
                command="execute",
                candidate_id=record.request.candidate_id,
                expected_digest=approved["result"]["record_digest"],
            ).model_dump(mode="json")
            body[change] = "forged"
            writer.write(json.dumps(body).encode() + b"\n")
            await writer.drain()
            assert not json.loads(await reader.readline())["ok"]
            writer.close()
            await writer.wait_closed()
        elif change == "policy":
            from soc_agent.policy import PolicyDecision, PolicyResult

            monkeypatch.setattr(
                monitor.simulation.policy,
                "evaluate",
                lambda _: PolicyResult(decision=PolicyDecision.DENY, reason="fixture denial"),
            )
            assert not (
                await operator_request(
                    root,
                    "execute",
                    candidate_id=record.request.candidate_id,
                    expected_digest=approved["result"]["record_digest"],
                )
            )["ok"]
        else:
            with monitor.pipeline.store.database.transaction() as c:
                c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
            assert not (
                await operator_request(
                    root,
                    "execute",
                    candidate_id=record.request.candidate_id,
                    expected_digest=approved["result"]["record_digest"],
                )
            )["ok"]
        assert monitor.simulation.load(record.request.candidate_id).status == "APPROVED"
        assert monitor.simulation.load(record.request.candidate_id).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_socket_symlink_mode_and_stale_recovery(tmp_path, monkeypatch):
    root, monitor, _ = await prepared(tmp_path, monkeypatch)
    server = OperatorServer(monitor, (os.geteuid(),))
    parent = root / "operator"
    parent.mkdir(mode=0o700)
    path = parent / "review.sock"
    path.symlink_to(root / "monitor.sqlite")
    with pytest.raises(ValueError):
        await server.start()
    path.unlink()
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(str(path))
    path.chmod(0o666)
    with pytest.raises(ValueError):
        await server.start()
    path.chmod(0o600)
    with exclusive_runtime_lock(root / "writer.lock"):
        await server.start()
        await server.close()
    with pytest.raises(ValueError):
        OperatorServer(monitor, (os.geteuid() + 1,))


@pytest.mark.asyncio
async def test_live_runtime_and_separate_operator_cli_process(tmp_path, monkeypatch):
    root, monitor, _ = await prepared(tmp_path, monkeypatch)
    running = asyncio.create_task(monitor.run(duration_seconds=5, operator_uids=(os.geteuid(),)))
    try:
        for _ in range(200):
            if (root / "operator/review.sock").exists():
                break
            await asyncio.sleep(0.01)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "soc_agent.linux_runtime",
            "--directory",
            str(root),
            "operator",
            "pending",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, stderr.decode()
        assert json.loads(stdout)["ok"]
        with pytest.raises(OSError):
            with exclusive_runtime_lock(root / "writer.lock"):
                pass
        assert monitor.store.state()["state"] == "RUNNING"
    finally:
        monitor.request_stop()
        await running
    assert monitor.store.state()["state"] == "STOPPED"
    assert not (root / "operator/review.sock").exists()


@pytest.mark.asyncio
async def test_audit_failure_blocks_review_and_stops_admission(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, server):
        original = monitor.store._audit

        def unavailable(*args):
            raise OSError("fixture audit unavailable")

        monkeypatch.setattr(monitor.store, "_audit", unavailable)
        reply = await send(root, "approve", record)
        assert not reply["ok"] and reply["status"] == "BLOCKED"
        assert monitor.stop_event.is_set() and server.closing
        monkeypatch.setattr(monitor.store, "_audit", original)
        assert monitor.simulation.load(record.request.candidate_id).status == "PENDING_REVIEW"
        assert monitor.simulation.load(record.request.candidate_id).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_incomplete_request_timeout_and_safe_shutdown(tmp_path, monkeypatch):
    import soc_agent.linux_runtime.operator as module

    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        monkeypatch.setattr(module, "TIMEOUT", 0.1)
        reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
        assert json.loads(await reader.readline())["protocol"] == module.PROTOCOL
        assert not json.loads(await reader.readline())["ok"]
        writer.close()
        await writer.wait_closed()
        monitor.request_stop()
        assert not (await send(root, "approve", record))["ok"]
        assert monitor.simulation.load(record.request.candidate_id).status == "PENDING_REVIEW"


@pytest.mark.asyncio
async def test_live_dispatch_race_has_one_simulator_invocation(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        approved = await send(root, "approve", record)
        kwargs = {
            "candidate_id": record.request.candidate_id,
            "expected_digest": approved["result"]["record_digest"],
        }
        replies = await asyncio.gather(
            operator_request(root, "execute", **kwargs), operator_request(root, "execute", **kwargs)
        )
        assert sum(r["ok"] for r in replies) == 1
        result = monitor.simulation.load(record.request.candidate_id)
        assert result.simulated_handler_calls == 1 and result.real_os_handler_calls == 0


@pytest.mark.asyncio
async def test_socket_parent_and_endpoint_are_not_redirectable(tmp_path, monkeypatch):
    root, monitor, _ = await prepared(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    (root / "operator").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        await OperatorServer(monitor, (os.geteuid(),)).start()
    assert not (outside / "review.sock").exists()


@pytest.mark.asyncio
async def test_request_rechecks_socket_permissions(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
        reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
        hello = json.loads(await reader.readline())
        (root / "operator/review.sock").chmod(0o666)
        body = OperatorRequest(
            request_id=uuid4(),
            challenge=hello["challenge"],
            created_at=utc_now(),
            command="approve",
            candidate_id=record.request.candidate_id,
            expected_digest=view(record)["record_digest"],
        )
        writer.write(body.model_dump_json().encode() + b"\n")
        await writer.drain()
        # Filesystem identity must be checked immediately before dispatch, too.
        reply = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        (root / "operator/review.sock").chmod(0o600)
        assert not reply["ok"]
        assert monitor.simulation.load(record.request.candidate_id).status == "PENDING_REVIEW"
