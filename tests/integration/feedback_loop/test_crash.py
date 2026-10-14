"""Owned fixture runtime children only, no foreign process or operating service signal."""

import asyncio
import json
import multiprocessing
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.feedback_loop.test_loop import prepared

from soc_agent.experience.runtime import capture_runtime_experience
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop
from soc_agent.linux_runtime.operator import OperatorServer
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector


def child(root, point, sender, nonce):
    LinuxAuthenticationCollector.poll = lambda *args: []
    monitor = LinuxMonitor(Path(root))
    commit = monitor.store.database._commit

    def pause():
        sender.send((os.getpid(), nonce, point))
        sender.recv()

    def committed(connection):
        row = connection.execute(
            "SELECT payload FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        hit = json.loads(row[0])["kind"] == "DIAGNOSTIC_FEEDBACK"
        if hit and point == "BEFORE_FEEDBACK_COMMIT":
            pause()
        commit(connection)
        if hit and point == "AFTER_FEEDBACK_COMMIT":
            pause()

    monitor.store.database._commit = committed
    asyncio.run(monitor.run(duration_seconds=20, operator_uids=(os.geteuid(),)))


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["BEFORE_FEEDBACK_COMMIT", "AFTER_FEEDBACK_COMMIT"])
async def test_owned_feedback_crash_and_idempotent_retransmission(tmp_path, monkeypatch, point):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        experience = capture_runtime_experience(monitor, ids[0])
    feedback_id = str(uuid4())
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe()
    nonce = str(uuid4())
    process = context.Process(target=child, args=(str(root), point, sender, nonce))
    process.start()
    sender.close()
    client = None
    command = [
        sys.executable,
        "-m",
        "soc_agent.linux_runtime",
        "--directory",
        str(root),
        "operator",
        "feedback-submit",
        ids[0],
        "--experience-id",
        experience.experience_id,
        "--feedback-id",
        feedback_id,
        "--label",
        "INCONCLUSIVE",
        "--reason-code",
        "INSUFFICIENT_CONTEXT",
    ]
    try:
        for _ in range(500):
            if (root / "operator/review.sock").exists():
                break
            await asyncio.sleep(0.01)
        client = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        await client.communicate()
        assert client.returncode != 0
        restored = LinuxMonitor(root)
        values = RuntimeFeedbackLoop(restored).records()
        assert len(values) == (1 if point == "AFTER_FEEDBACK_COMMIT" else 0)
        old = values[0] if values else None
        # Existing lifetime lock is reacquired before stale socket replacement.
        from soc_agent.runtime_lock import exclusive_runtime_lock

        server = OperatorServer(restored, (os.geteuid(),))
        with exclusive_runtime_lock(root / "writer.lock"):
            await server.start()
            try:
                retry = await asyncio.create_subprocess_exec(
                    *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                output, error = await retry.communicate()
                assert retry.returncode == 0, error.decode()
            finally:
                await server.close()
        values = RuntimeFeedbackLoop(restored).records()
        assert len(values) == 1
        if old:
            assert values[0] == old
        assert (await security_check(restored.pipeline))["write_spy_calls"] == 0
        assert restored.store.verify_audit()
        for db in (
            restored.store.database,
            restored.pipeline.store.database,
            restored.pipeline.queue.database,
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
