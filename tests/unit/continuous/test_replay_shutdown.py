"""Actual owned child with a saturated pipe; no collector, network or model execution."""

import asyncio
import sys

import pytest
from tests.unit.continuous.test_runtime import config

from soc_agent.continuous.source import ReplaySource


@pytest.mark.asyncio
async def test_early_replay_shutdown_reaps_and_drains_concurrent_closers(tmp_path):
    source = ReplaySource(config(tmp_path))
    source.process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import os,time; os.write(1, b'x' * 262144); time.sleep(30)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        limit=1024,
    )
    try:
        # Receiving a byte proves the producer started; leave the rest unread.
        assert await asyncio.wait_for(source.process.stdout.read(1), 3) == b"x"
        await asyncio.wait_for(asyncio.gather(source.close(), source.close()), 7)
        assert source.process.returncode is not None
        assert source.process.stdout.at_eof()
        await source.close()  # Idempotent after real process exit and EOF.
    finally:
        if source.process.returncode is None:
            source.process.kill()
        await source.process.communicate()
