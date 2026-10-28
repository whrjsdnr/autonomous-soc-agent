"""Nonprivileged read-only sources. No helper authentication, sudo, socket or capture."""

import asyncio
import json
import os
from pathlib import Path

from soc_agent.continuous.models import require_source_authority
from soc_agent.security_ai.research.environment import read_local


class ReplaySource:
    def __init__(self, config):
        self.config = config
        self.process = None

    async def events(self):
        import hashlib

        require_source_authority(self.config)
        if self.config.source == "JSONL_REPLAY":
            body = await asyncio.to_thread(read_local, self.config.input_file, 16 * 1024**2)
            if hashlib.sha256(body).hexdigest() != self.config.input_sha256:
                raise ValueError("CONTINUOUS_INPUT_SHA")
            if not body.endswith(b"\n"):
                raise ValueError("CONTINUOUS_PARTIAL_SOURCE_RECORD")
            for line in body.splitlines():
                if len(line) > 262144:
                    raise ValueError("CONTINUOUS_SOURCE_RECORD_BOUND")
                yield json.loads(line)
                await asyncio.sleep(self.config.replay_delay_seconds)
            return
        if not self.config.ml_root:
            raise ValueError("CONTINUOUS_EXISTING_ML_ROOT_REQUIRED")
        root = Path(__file__).parents[2]
        python = (
            self.config.ml_root.parent
            / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
        )
        self.process = await asyncio.create_subprocess_exec(
            str(python),
            "-m",
            "soc_agent.continuous.source_worker",
            "--parent-pid",
            str(os.getpid()),
            "--ml",
            str(self.config.ml_root),
            "--input",
            str(self.config.input_file),
            "--sha",
            self.config.input_sha256,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={
                "PATH": os.defpath,
                "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1",
                "LANG": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": str(root) + os.pathsep + str(self.config.ml_root / "src"),
            },
        )
        try:
            while line := await self.process.stdout.readline():
                if len(line) > 262144:
                    raise ValueError("CONTINUOUS_SOURCE_RECORD_BOUND")
                yield json.loads(line)
                await asyncio.sleep(self.config.replay_delay_seconds)
            if await self.process.wait() != 0:
                raise ValueError("CONTINUOUS_SOURCE_WORKER_FAILED")
        finally:
            await self.close()

    async def close(self):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 3)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
