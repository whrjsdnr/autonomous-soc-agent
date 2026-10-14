"""Owned runtime process + independent CLI; kill only nonce/PID/lock-verified children."""

import asyncio
import json
import multiprocessing
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.live_operator.test_operator import endpoint, send
from tests.integration.response_simulation.test_runtime_simulation import prepared

from soc_agent.linux_runtime.operator import view
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector

POINTS = ("REQUEST_COMMIT", "APPROVAL_COMMIT", "SIMULATION_RESERVATION", "SIMULATION_RECEIPT")


def runtime_child(root, point, pipe, nonce):
    # Sources were fixture-parsed in the parent, not live OS records. No collection side effects.
    LinuxAuthenticationCollector.poll = lambda *args: []
    monitor = LinuxMonitor(Path(root))
    commit = monitor.store.database._commit
    with monitor.store.database.transaction(write=False) as c:
        initial = c.execute("SELECT MAX(sequence) FROM monitor_audit").fetchone()[0]

    def committed(connection):
        commit(connection)
        row = connection.execute(
            "SELECT sequence,payload FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        body = json.loads(row["payload"])
        if row["sequence"] <= initial:
            return
        status = body["details"].get("record", {}).get("status")
        hit = point == "REQUEST_COMMIT" and body["kind"] == "OPERATOR_REQUEST"
        hit |= point == "APPROVAL_COMMIT" and status == "APPROVED"
        hit |= point == "SIMULATION_RESERVATION" and status == "STARTED"
        hit |= point == "SIMULATION_RECEIPT" and status == "SIMULATED"
        if hit:
            pipe.send((os.getpid(), nonce, point))
            pipe.recv()

    monitor.store.database._commit = committed
    asyncio.run(monitor.run(duration_seconds=20, operator_uids=(os.geteuid(),)))


@pytest.mark.asyncio
@pytest.mark.parametrize("point", POINTS)
async def test_live_operator_owned_crash_restores_decision_and_result(tmp_path, monkeypatch, point):
    if point.startswith("SIMULATION"):
        async with endpoint(tmp_path, monkeypatch) as (root, monitor, record, _):
            assert (await send(root, "approve", record))["ok"]
            record = monitor.simulation.load(record.request.candidate_id)
    else:
        root, monitor, record = await prepared(tmp_path, monkeypatch)
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe()
    nonce = str(uuid4())
    process = context.Process(target=runtime_child, args=(str(root), point, sender, nonce))
    process.start()
    sender.close()
    client = None
    try:
        for _ in range(500):
            if (root / "operator/review.sock").exists():
                break
            await asyncio.sleep(0.01)
        assert process.is_alive()
        command = "execute" if point.startswith("SIMULATION") else "approve"
        client = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "soc_agent.linux_runtime",
            "--directory",
            str(root),
            "operator",
            command,
            record.request.candidate_id,
            "--expected-digest",
            view(record)["record_digest"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        stdout, stderr = await client.communicate()
        assert (
            client.returncode != 0
        )  # No success acknowledgment on interrupted response transport.
        restarted = LinuxMonitor(root)
        await restarted.run(duration_seconds=0.2, operator_uids=(os.geteuid(),))
        restored = restarted.simulation.load(record.request.candidate_id)
        expected = {
            "REQUEST_COMMIT": "PENDING_REVIEW",
            "APPROVAL_COMMIT": "APPROVED",
            "SIMULATION_RESERVATION": "UNCERTAIN",
            "SIMULATION_RECEIPT": "SIMULATED",
        }[point]
        assert restored.status == expected
        assert restored.real_os_handler_calls == 0
        assert restored.actor_assurance == (
            "EXPLICIT_TEST_IDENTITY"
            if point == "REQUEST_COMMIT" and record.approval.decision
            else "NO_DECISION"
            if point == "REQUEST_COMMIT"
            else "OS_PEER_IDENTITY"
        )
        assert restarted.store.verify_audit()
        assert (await security_check(restarted.pipeline))["write_spy_calls"] == 0
        for db in (
            restarted.store.database,
            restarted.pipeline.queue.database,
            restarted.pipeline.store.database,
        ):
            with db.transaction(write=False) as c:
                assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()
        if client is not None and client.returncode is None:
            await client.communicate()
