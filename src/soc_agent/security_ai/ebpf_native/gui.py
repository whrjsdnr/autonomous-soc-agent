"""Application-session phase-A presentation on the existing four-screen Desktop."""

from soc_agent.gui.production import Desktop
from soc_agent.gui.worker import Worker
from soc_agent.security_ai.ebpf_native.application import Application


class Backend:
    def __init__(self, application: Application):
        self.application = application

    async def production_status(self) -> dict:
        return self.application.snapshot()

    async def phase_start(self) -> dict:
        return self.application.start(self.application.scope)

    async def collector_stop(self) -> dict:
        return self.application.stop()

    async def close(self, reason="GUI_CLOSE") -> None:
        self.application.close()


class PhaseWorker(Worker):
    async def _create(self, application):
        return Backend(application)


class PhaseDesktop(Desktop):
    def start(self):
        self.call("phase_start", callback=self.render)

    def _render_current(self):
        previous = self.last_render
        super()._render_current()
        if self.page != "System" or self.last_render == previous:
            return
        detail = self.snapshot.get("ebpf", {})
        current = self.system.get("1.0", "end")
        lines = [
            "",
            "APPLICATION SESSION · PHASE A / NO KERNEL LOAD",
            "Password policy   ONCE PER APPLICATION / Native authentication PENDING",
            "Authentication   " + str(detail.get("authentication_state", "REQUIRED")),
            "Loader SHA   " + str(detail.get("loader_sha256", "UNKNOWN")),
            "Bundle digest   " + str(detail.get("bundle_digest", "UNKNOWN")),
            "Hook state   " + str(detail.get("hook_state", "NATIVE_PENDING")),
            "Supervisor   " + str(detail.get("supervisor_state", "NOT_STARTED")),
            "Cleanup   " + str(detail.get("cleanup_status", "NOT_OBSERVED")),
            "Native AI   BLOCKED",
        ]
        self._text(self.system, current + "\n".join(lines))
        self.copy_button.configure(state="disabled")
        self.start_button.configure(
            state="normal"
            if detail.get("authentication_state") == "MOCK_VERIFIED_NOT_NATIVE"
            and self.snapshot.get("state") in {"AUTHENTICATED", "CLOSED"}
            else "disabled"
        )


def launch(application: Application) -> int:
    import tkinter as tk

    from soc_agent.gui.backend import GUIConfig

    root = tk.Tk()
    PhaseDesktop(
        root, GUIConfig(data_directory=application.directory), worker=PhaseWorker(application)
    )
    root.title("SOC PHASE A · MOCK AUTHENTICATION / NO NATIVE HOOK")
    root.mainloop()
    return 0
