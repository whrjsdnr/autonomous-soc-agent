"""Collector capability boundary; the existing capture runtime remains its sole owner."""

from typing import Protocol


class Collector(Protocol):
    async def prepare(self, **options) -> dict: ...
    async def start(self) -> dict: ...
    async def stop(self) -> dict: ...
    def health(self) -> dict: ...
    def network_events(self) -> list[dict]: ...
    def dns_events(self) -> list[dict]: ...
    def metrics(self) -> dict: ...
    def snapshot(self) -> dict: ...
    async def recover(self) -> dict: ...


class ExistingCaptureCollectorAdapter:
    """Forward ownership; never create another runtime/worker or launch capture."""

    def __init__(self, owner):
        self.owner = owner

    async def prepare(self, **options):
        return await self.owner.start(**options)

    async def start(self):
        return self.owner.snapshot()  # Authentication remains explicit elsewhere.

    async def stop(self):
        await self.owner.stop()
        return self.owner.snapshot()

    def health(self):
        return {"state": self.owner.state}

    def network_events(self):
        return self.owner.snapshot().get("research", {}).get("records", [])

    def dns_events(self):
        return self.owner.snapshot().get("dns", {}).get("events", [])

    def metrics(self):
        return self.owner.snapshot().get("network", {})

    def snapshot(self):
        return self.owner.snapshot()

    async def recover(self):
        return await self.owner.restore_latest()
