"""Real runtime process + independent CLI; source events are explicitly fixture-seeded."""

import asyncio
import json
import multiprocessing
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from tests.integration.restricted_response.test_executor import prepare

from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector


def runtime_child(root, channel, nonce):
    LinuxAuthenticationCollector.poll = lambda *args: []  # No native-source claim or provider call.
    monitor = LinuxMonitor(Path(root))

    async def run():
        task = asyncio.create_task(monitor.run(duration_seconds=30, operator_uids=(os.geteuid(),)))
        while not (Path(root) / "operator/review.sock").exists():
            if task.done():
                await task
                raise AssertionError("ENDPOINT_NOT_STARTED")
            await asyncio.sleep(0.01)
        channel.send((os.getpid(), nonce))
        await task

    asyncio.run(run())


async def cli(root, *arguments):
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "soc_agent.linux_runtime.restricted_cli",
        "--directory",
        str(root),
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[3] / "src")},
    )
    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15)
    assert process.returncode == 0
    value = json.loads(stdout)
    assert value["ok"]
    return value["result"]


@pytest.mark.asyncio
async def test_independent_cli_live_execution_and_approved_rollback(tmp_path, monkeypatch):
    root, monitor, finding, _ = await prepare(tmp_path, monkeypatch)
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe()
    nonce = str(uuid4())
    process = context.Process(target=runtime_child, args=(str(root), sender, nonce))
    process.start()
    sender.close()
    try:
        assert await asyncio.to_thread(parent.poll, 20)
        assert parent.recv() == (process.pid, nonce)
        assert process.is_alive() and process in multiprocessing.active_children()
        listed = await cli(root, "list")
        assert listed["restricted_executor_enabled"] and not listed["automatic_approval"]
        pending = await cli(root, "request", finding)
        identity = pending["record"]["candidate_id"]
        approval = await cli(
            root, "approve", identity, "--expected-digest", pending["record_digest"]
        )
        done = await cli(root, "execute", identity, "--expected-digest", approval["record_digest"])
        assert done["status"] == "TEST_RESOURCE_CHANGED"
        assert (root / "test-resources/marker").read_bytes() == QUARANTINED
        assert done["record"]["receipt"]["operator_uid"] == os.geteuid()
        rollback = await cli(root, "rollback-request", finding, identity)
        rollback_id = rollback["record"]["candidate_id"]
        reviewed = await cli(
            root, "approve", rollback_id, "--expected-digest", rollback["record_digest"]
        )
        restored = await cli(
            root, "execute", rollback_id, "--expected-digest", reviewed["record_digest"]
        )
        assert restored["status"] == "ROLLED_BACK"
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE
        # Existing authenticated local stop flag, not killing an external OS process.
        monitor.store.request_stop(True)
        await asyncio.to_thread(process.join, 10)
        assert process.exitcode == 0
        assert monitor.store.verify_audit()
    finally:
        if process.is_alive():
            assert process in multiprocessing.active_children()
            process.kill()
            process.join(10)
        process.close()
        parent.close()
