"""One owned backend loop shared by production and developer desktop modes."""

import asyncio
import threading

from soc_agent.gui.backend import Backend


class Worker:
    def __init__(self, config):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self.loop.run_forever, name="soc-gui-backend", daemon=True
        )
        self.thread.start()
        try:
            self.backend = asyncio.run_coroutine_threadsafe(self._create(config), self.loop).result(
                10
            )
        except Exception:
            self.shutdown()
            raise

    async def _create(self, config):
        return Backend(config)

    def submit(self, operation, *args, **kwargs):
        async def execute():
            method = getattr(self.backend, operation)
            value = method(*args, **kwargs)
            return await value if asyncio.iscoroutine(value) else value

        return asyncio.run_coroutine_threadsafe(execute(), self.loop)

    def shutdown(self):
        async def release():
            await self.loop.shutdown_asyncgens()
            await self.loop.shutdown_default_executor(timeout=3)

        asyncio.run_coroutine_threadsafe(release(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(2)
        if self.thread.is_alive():
            raise RuntimeError("GUI_WORKER_SHUTDOWN_UNCERTAIN")
        self.loop.close()
