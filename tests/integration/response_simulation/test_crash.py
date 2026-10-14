"""Only owned fixture children are killed, only pure simulator handlers are installed."""

import asyncio
import json
import multiprocessing
import os
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.response_simulation.test_runtime_simulation import prepared

from soc_agent.execution import GovernedExecutor
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock

POINTS = ("RESERVATION_COMMIT", "HANDLER_RETURN", "RECEIPT_COMMIT")


def child(root, identity, point, pipe, nonce):
    with exclusive_runtime_lock(Path(root) / "writer.lock"):
        monitor = LinuxMonitor(Path(root))
        simulation = monitor.simulation
        execute = GovernedExecutor.execute
        commit = monitor.store.database._commit

        def pause():
            pipe.send((os.getpid(), nonce, point))
            pipe.recv()

        async def dispatch(self, *args, **kwargs):
            if point == "RESERVATION_COMMIT":
                pause()
            result = await execute(self, *args, **kwargs)
            if point == "HANDLER_RETURN":
                pause()
            return result

        def committing(connection):
            commit(connection)
            last = connection.execute(
                "SELECT payload FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            body = json.loads(last[0])
            if (
                point == "RECEIPT_COMMIT"
                and body["kind"] == "SIMULATION_RECORD"
                and body["details"]["record"]["status"] == "SIMULATED"
            ):
                pause()

        GovernedExecutor.execute = dispatch
        monitor.store.database._commit = committing
        asyncio.run(simulation.execute(identity))


@pytest.mark.asyncio
@pytest.mark.parametrize("point", POINTS)
async def test_owned_simulation_crash_preserves_lineage_and_blocks_replay(
    tmp_path, monkeypatch, point
):
    root, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:crash-reviewer")
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe(duplex=True)
    nonce = str(uuid4())
    process = context.Process(target=child, args=(str(root), identity, point, sender, nonce))
    process.start()
    sender.close()
    try:
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        restarted = LinuxMonitor(root)
        with exclusive_runtime_lock(root / "writer.lock"):
            restarted.simulation.recover()
            value = restarted.simulation.load(identity)
            assert value.status == ("SIMULATED" if point == "RECEIPT_COMMIT" else "UNCERTAIN")
            assert value.request == record.request
            assert value.real_os_handler_calls == 0
            assert value.simulated_handler_calls == (1 if point == "RECEIPT_COMMIT" else None)
            with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
                await restarted.simulation.execute(identity)
            for db in (
                restarted.store.database,
                restarted.pipeline.queue.database,
                restarted.pipeline.store.database,
            ):
                with db.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert (await security_check(restarted.pipeline))["write_spy_calls"] == 0
            assert restarted.store.verify_audit()
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()
