"""The existing four-screen Desktop with Phase B-1 fixture ownership details."""

from soc_agent.gui.production import Desktop
from soc_agent.gui.worker import Worker
from soc_agent.security_ai.ebpf_broker.controller import Controller


class Backend:
    def __init__(self, controller: Controller):
        self.controller = controller

    async def production_status(self):
        return self.controller.observe()

    async def broker_start(self):
        return self.controller.start()

    async def collector_stop(self):
        return self.controller.stop()

    async def close(self, reason="GUI_CLOSE"):
        self.controller.close()


class BrokerWorker(Worker):
    async def _create(self, controller):
        return Backend(controller)


class BrokerDesktop(Desktop):
    def start(self):
        self.call("broker_start", callback=self.render)

    def _render_current(self):
        previous = self.last_render
        super()._render_current()
        if self.page != "System" or previous == self.last_render:
            return
        detail = self.snapshot.get("ebpf", {})
        text = self.system.get("1.0", "end")
        rows = ["", "BROKER PHASE B-1 · MOCK AUTH / NO NATIVE HOOK"]
        for title, key in (
            ("Authentication", "authentication_state"),
            ("Broker", "broker_state"),
            ("Hook", "hook_state"),
            ("Ownership", "hook_ownership"),
            ("Cleanup", "cleanup_status"),
            ("Program SHA", "program_sha256"),
            ("Bundle", "bundle_digest"),
            ("Broker SHA", "broker_sha256"),
        ):
            rows.append(title + "   " + str(detail.get(key, "UNKNOWN")))
        rows.append("Native AI / DNS9 / Operational promotion   BLOCKED")
        self._text(self.system, text + "\n".join(rows))
        self.copy_button.configure(state="disabled")
        self.start_button.configure(
            state="normal"
            if (
                detail.get("authentication_state") == "MOCK_VERIFIED_NOT_NATIVE"
                and self.snapshot.get("state") in {"BROKER_READY", "CLOSED"}
            )
            else "disabled"
        )


def launch(controller: Controller) -> int:
    import tkinter as tk

    from soc_agent.gui.backend import GUIConfig

    root = tk.Tk()
    BrokerDesktop(
        root,
        GUIConfig(data_directory=controller.application.directory),
        worker=BrokerWorker(controller),
    )
    root.title("SOC BROKER B-1 · MOCK AUTHENTICATION / NO KERNEL HOOK")
    root.mainloop()
    return 0
