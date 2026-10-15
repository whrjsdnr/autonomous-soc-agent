"""An explicitly started Runtime outlives its GUI; no pipe/async transport owns its life."""

import asyncio
import subprocess


class PersistentRuntimeProcess:
    def __init__(self, args: list[str], log):
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            shell=False,
        )

    @property
    def returncode(self):
        return self.process.poll()

    @property
    def pid(self):
        return self.process.pid

    async def wait(self):
        return await asyncio.to_thread(self.process.wait)

    def terminate(self):
        # Only used by the explicit Stop button on this owned Runtime.
        self.process.terminate()
