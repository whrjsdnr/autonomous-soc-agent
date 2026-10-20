"""Reuse the four-screen Desktop and one Worker, with a preparation-only backend."""

from soc_agent.gui.worker import Worker
from soc_agent.security_ai.ebpf.collector import EBPFCollector


class PreparationBackend:
    def __init__(self, owner: EBPFCollector):
        self.owner = owner

    async def production_status(self) -> dict:
        if self.owner.state == "IDLE":
            await self.owner.prepare()
        return self.owner.snapshot()

    async def collector_stop(self) -> dict:
        return await self.owner.stop()

    async def close(self, reason="GUI_CLOSE") -> None:
        await self.owner.stop()


class PreparationWorker(Worker):
    async def _create(self, owner):
        return PreparationBackend(owner)


def launch(owner: EBPFCollector) -> int:
    import tkinter as tk

    from soc_agent.gui.backend import GUIConfig
    from soc_agent.gui.production import Desktop

    root = tk.Tk()
    app = Desktop(root, GUIConfig(data_directory=owner.directory), worker=PreparationWorker(owner))
    # Reuse terminal-managed Start guard; no authentication, Capture or stale command.
    app.terminal_managed = True
    root.title("SOC Command Center · EBPF_TC PREPARATION ONLY / NATIVE HOOK PENDING")
    root.mainloop()
    return 0
