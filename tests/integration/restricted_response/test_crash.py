"""Owned child-process interruption: real test-file effects, fixture source evidence."""

import asyncio
import json
import multiprocessing
import os
import socket
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.restricted_response.test_executor import approved, command, endpoint, request

from soc_agent.execution import GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.linux_runtime.restricted_models import RestrictedInput
from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED
from soc_agent.linux_runtime.restricted_response import RestrictedResponseExecutor
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view

POINTS = (
    "AFTER_APPROVAL",
    "BEFORE_CHANGE",
    "AFTER_CHANGE",
    "BEFORE_RECEIPT",
    "BEFORE_AUDIT",
    "BEFORE_ROLLBACK",
    "AFTER_ROLLBACK",
    "BEFORE_ROLLBACK_AUDIT",
    "AFTER_RECEIPT_COMMIT",
)


def child(root, candidate, point, pipe, nonce):
    directory = Path(root)
    with exclusive_runtime_lock(directory / "writer.lock"):
        monitor = LinuxMonitor(directory)
        monitor.store.update(state="RUNNING")
        executor = RestrictedResponseExecutor(monitor)

        def pause():
            pipe.send((os.getpid(), nonce, point))
            pipe.recv()

        preflight = GovernedExecutor.preflight

        def checked(self, *args, **kwargs):
            result = preflight(self, *args, **kwargs)
            if point == "AFTER_APPROVAL":
                pause()
            return result

        GovernedExecutor.preflight = checked
        change = executor.resource.change

        def changed(*args, **kwargs):
            if point in ("BEFORE_CHANGE", "BEFORE_ROLLBACK"):
                pause()
            result = change(*args, **kwargs)
            if point in ("AFTER_CHANGE", "AFTER_ROLLBACK"):
                pause()
            return result

        executor.resource.change = changed
        save = executor._save

        def saving(c, record):
            if point == "BEFORE_RECEIPT" and record.status == "TEST_RESOURCE_CHANGED":
                pause()
            return save(c, record)

        executor._save = saving
        audit = monitor.store._audit

        def auditing(c, kind, details):
            if kind == "RESTRICTED_RECORD" and (
                point == "BEFORE_AUDIT"
                and details["record"]["status"] == "TEST_RESOURCE_CHANGED"
                or point == "BEFORE_ROLLBACK_AUDIT"
                and details["record"]["status"] == "ROLLED_BACK"
            ):
                pause()
            return audit(c, kind, details)

        monitor.store._audit = auditing
        commit = monitor.store.database._commit

        def committed(c):
            commit(c)
            if point == "AFTER_RECEIPT_COMMIT":
                body = json.loads(
                    c.execute(
                        "SELECT payload FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()[0]
                )
                if (
                    body["kind"] == "RESTRICTED_RECORD"
                    and body["details"]["record"]["status"] == "TEST_RESOURCE_CHANGED"
                ):
                    pause()

        monitor.store.database._commit = committed
        record = next(r for r in executor.records() if r.candidate_id == candidate)
        local, peer = socket.socketpair()
        try:
            asyncio.run(executor.execute(candidate, sock=local, expected_digest=record.digest))
        finally:
            local.close()
            peer.close()
        raise AssertionError("CRASH_POINT_NOT_REACHED")


@pytest.mark.asyncio
@pytest.mark.parametrize("point", POINTS)
async def test_owned_crash_reconciles_marker_without_repeating_effect(tmp_path, monkeypatch, point):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, _):
        action = await approved(root, finding)
        if "ROLLBACK" in point:
            done = await command(root, "execute", action)
            rollback = await request(root, finding, done["result"]["record"]["candidate_id"])
            reviewed = await command(root, "approve", rollback)
            action = reviewed["result"]
        source = read_authentication_view(monitor.pipeline)
    candidate = action["record"]["candidate_id"]
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe()
    nonce = str(uuid4())
    process = context.Process(target=child, args=(str(root), candidate, point, sender, nonce))
    process.start()
    sender.close()
    try:
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        restored = LinuxMonitor(root)
        await restored.run(duration_seconds=0.2, operator_uids=(os.geteuid(),))
        executor = RestrictedResponseExecutor(restored)
        record = next(r for r in executor.records() if r.candidate_id == candidate)
        expected_status = (
            "APPROVED"
            if point == "AFTER_APPROVAL"
            else "TEST_RESOURCE_CHANGED"
            if point == "AFTER_RECEIPT_COMMIT"
            else "UNKNOWN"
        )
        assert record.status == expected_status
        if record.receipt is not None:
            assert record.receipt.operator_uid == os.geteuid()
            assert record.approval.decision.decided_by == f"os-uid:{record.receipt.operator_uid}"
        expected = (
            AVAILABLE
            if point
            in ("AFTER_APPROVAL", "BEFORE_CHANGE", "AFTER_ROLLBACK", "BEFORE_ROLLBACK_AUDIT")
            else QUARANTINED
        )
        marker = root / "test-resources/marker"
        assert marker.read_bytes() == expected
        assert read_authentication_view(restored.pipeline) == source
        assert (await security_check(restored.pipeline))["write_spy_calls"] == 0
        assert restored.store.verify_audit()
        if point != "AFTER_APPROVAL":
            local, peer = socket.socketpair()
            try:
                with pytest.raises(ExecutionDeniedError):
                    await executor.execute(candidate, sock=local, expected_digest=record.digest)
            finally:
                local.close()
                peer.close()
            assert marker.read_bytes() == expected
        if record.status == "UNKNOWN":
            assert record.receipt is None
            value = RestrictedInput.model_validate(record.action.input_payload())
            assert record.observed_digest is not None
            assert record.recovery_observation == (
                "UNCHANGED" if record.observed_digest == value.before_digest else "EXPECTED_AFTER"
            )
        for database in (
            restored.store.database,
            restored.pipeline.queue.database,
            restored.pipeline.store.database,
        ):
            with database.transaction(write=False) as c:
                assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()
