"""One terminal approval/authentication, one controller loop, one non-root GUI.

This module never reads a password. Only StreamProcess.authenticate invokes the
OS terminal authentication API; capture is deferred until the GUI is ready.
"""

import os
import sqlite3
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

from soc_agent.gui.backend import GUIConfig
from soc_agent.gui.worker import Worker
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.collectors.finalization import publish
from soc_agent.security_ai.collectors.handoff import read_controller, safe_code
from soc_agent.security_ai.collectors.live_contract import bundle, verify
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.operational.network_capture.calibrated_policy import require_headroom
from soc_agent.security_ai.operational.network_capture.live_session import unprivileged


def preflight():
    unprivileged()
    if not sys.stdin.isatty():
        raise ValueError("TOTAL_INTERACTIVE_TERMINAL_REQUIRED")
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise ValueError("TOTAL_WSLG_DISPLAY_REQUIRED")
    import tkinter  # noqa: F401

    require_headroom()
    pressure = Path("/proc/pressure/memory").read_text()
    if float(pressure.split("avg10=", 1)[1].split()[0]) >= 1:
        raise ValueError("ZEEK_RESOURCE_PRESSURE_REQUIRED")
    OfflineZeek().environment()
    # Read-only inventory. Never clean up an old or unverified capture implicitly.
    result = subprocess.run(
        ["docker", "container", "ls", "--all", "--filter", "name=soc-zeek-", "--format", "{{.ID}}"],
        capture_output=True,
        timeout=3,
        check=False,
    )
    if result.returncode or result.stdout.strip():
        raise ValueError("ZEEK_PRIOR_CONTAINER_REVIEW_REQUIRED")


class Startup:
    """The original backend owns the listener across approval, auth and GUI startup."""

    def __init__(self, config: GUIConfig):
        self.config = config
        self.worker = Worker(config)
        self.runner = None
        self.phase = "PREPARING"
        self.error = None
        self.gui_started = False
        self.outcome = None

    def prepare(self):
        self.worker.submit("zeek_live_prepare").result(20)
        owner = self.worker.backend._owners["zeek_collector"]
        self.runner = StreamProcess(owner.directory, owner.plan)
        self.set_phase("APPROVAL_REQUIRED")
        return self.runner

    def set_phase(self, phase):
        plan = self.runner.plan
        self.worker.submit(
            "zeek_startup_phase",
            str(plan.session_id),
            plan.identity,
            str(plan.controller_generation),
            phase,
        ).result(5)
        self.phase = phase

    def scope(self):
        p = self.runner.plan
        hashes = bundle()
        controller = read_controller(self.runner.directory, p)
        return (
            "Zeek 9.0.0 / Native diagnostics; Native AI, DNS9, operational gate BLOCKED\n"
            f"Session: {p.session_id}\nPlan approval digest: {p.identity}\n"
            f"Controller: PID {controller.pid}, start ticks {controller.start_ticks}\n"
            f"Controller generation: {p.controller_generation}\nImage: {p.image}\n"
            f"Launcher SHA256: {hashes['live_process.py']}\nBundle digest: {p.bundle_digest}\n"
            "Interface lo; host network namespace; container NET_RAW only; non-root GUI/CLI\n"
            "300s from launch; 4096 packet records; 8192 events; 8MiB output; queue 32\n"
            "CPU 1; RAM 512MiB; private tmpfs 16MiB; no raw payload retention\n"
            "Terminal sudo authentication; fixed start/inspect/stop commands; no sudoers changes\n"
            "Approval applies once to this session. Stop: GUI Stop or Ctrl+C; no automatic retry."
        )

    def authenticate(self):
        self.set_phase("AUTHENTICATING")
        self.runner.authenticate()  # Main thread, inherited terminal; no capture yet.
        self.set_phase("STARTING")

    def gui_ready(self, desktop):
        if self.gui_started or self.phase != "STARTING":
            raise ValueError("ZEEK_STARTUP_PHASE_INVALID")
        self.gui_started = True
        desktop.call("zeek_launch_authenticated", self.runner, callback=desktop.render)

    def finish(self, reason="PREPARATION_CANCELLED"):
        try:
            if self.worker.thread.is_alive():
                if self.error:
                    self.worker.submit("zeek_startup_failure", self.error).result(5)
                self.worker.submit("close", reason).result(35)
                self.worker.shutdown()
            self.outcome = self.worker.backend.startup_outcome
            if self.outcome is None:
                raise ValueError("ZEEK_SHUTDOWN_UNVERIFIED")
            if self.outcome.get("last_error"):
                self.error = self.error or safe_code(self.outcome["last_error"])
            if (
                self.gui_started
                and not self.outcome.get("capture_start_attempted")
                and not self.error
            ):
                self.error = "ZEEK_COLLECTOR_NOT_STARTED"
            if self.runner:
                publish(
                    self.runner.directory / "cli-exit.json",
                    dict(
                        contract="soc-zeek-one-command-exit:v1",
                        session_id=str(self.runner.plan.session_id),
                        plan_digest=self.runner.plan.identity,
                        generation=str(self.runner.plan.controller_generation),
                        phase=self.phase,
                        error=self.error,
                        gui_ready=self.gui_started,
                        **self.outcome,
                    ),
                )
            return bool(self.outcome["safe_shutdown"])
        except (OSError, ValueError, TimeoutError, RuntimeError, sqlite3.Error):
            self.error = self.error or "ZEEK_SHUTDOWN_UNVERIFIED"
            return False


def start(directory: Path | None = None):
    from soc_agent.gui.__main__ import main as gui_main

    preflight()
    data = (
        directory
        or Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
        / "autonomous-soc-agent/gui"
    ).absolute()
    create_private_directory(data)
    # Lock before authentication; keep the same controller and lock through GUI exit.
    with ExitStack() as stack:
        if not (data / "desktop.lock").exists():
            create_private_file(data / "desktop.lock")
        stack.enter_context(exclusive_runtime_lock(data / "desktop.lock"))
        startup = Startup(GUIConfig(data_directory=data, collector_type="zeek-live"))
        result = 1
        reason = "PREPARATION_CANCELLED"
        try:
            runner = startup.prepare()
            create_private_file(runner.directory / "launcher.lock")
            stack.enter_context(exclusive_runtime_lock(runner.directory / "launcher.lock"))
            print(startup.scope(), flush=True)
            if input("Approve this session scope? [yes/NO] ").strip() != "yes":
                raise ValueError("ZEEK_SCOPE_APPROVAL_CANCELLED")
            verify(runner.plan, runner.plan.identity)
            startup.authenticate()
            reason = "GUI_CLOSE"
            result = gui_main(
                ["--collector", "zeek-live", "--data-directory", str(data)],
                prepared=startup,
            )
            if result:
                startup.error = "ZEEK_GUI_START_FAILED"
            elif not startup.gui_started:
                startup.error = "ZEEK_COLLECTOR_NOT_STARTED"
        except KeyboardInterrupt:
            startup.error = (
                "ZEEK_AUTH_INTERRUPTED"
                if startup.phase == "AUTHENTICATING"
                else "ZEEK_STARTUP_INTERRUPTED"
            )
            reason = "USER_STOP"
        except (EOFError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            startup.error = safe_code(error)
            reason = "LAUNCH_FAILED"
        finally:
            safe = startup.finish(reason)
        if not safe or startup.error:
            print(
                "Zeek startup BLOCKED: " + (startup.error or "ZEEK_SHUTDOWN_UNVERIFIED"),
                file=sys.stderr,
            )
            return 1
        return result
