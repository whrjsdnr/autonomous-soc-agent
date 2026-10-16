"""User-triggered OS authentication. No password API, shell, sudo or stored credential."""

import asyncio
import os
import shutil
import stat
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.stream_session import MODULE, load
from soc_agent.security_ai.research.models import digest

AGENTS = (
    "polkit-gnome-authentication-agent",
    "polkit-kde-authentication-agent",
    "lxqt-policykit-agent",
    "mate-polkit",
    "hyprpolkitagent",
)


def support():
    pkexec = shutil.which("pkexec")
    found = False
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            command = path.read_bytes().split(b"\0", 1)[0].decode(errors="replace")
            if any(Path(command).name.startswith(name) for name in AGENTS):
                found = True
        except OSError:
            continue
    usable = bool(
        pkexec
        and found
        and Path("/run/dbus/system_bus_socket").exists()
        and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    )
    return dict(
        status="OS_AUTH_UI_AVAILABLE_UNTESTED" if usable else "OS_AUTH_UI_UNAVAILABLE",
        pkexec_installed=pkexec is not None,
        agent_detected=found,
        requires_user_action=True,
        password_handled_by="OS_ONLY",
        native_authentication_verified=False,
    )


def arguments(session):
    # No arbitrary executable/module/flags from events or LLM output.
    launcher = Path("/usr/bin/setpriv")
    info = launcher.stat()
    if (
        info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not info.st_mode & stat.S_IXUSR
    ):
        raise ValueError("OS_AUTH_PRIVILEGE_LAUNCHER_UNTRUSTED")
    return [
        str(launcher),
        f"--reuid={session.uid}",
        f"--regid={session.gid}",
        "--clear-groups",
        "--bounding-set=-all,+net_raw",
        "--inh-caps=-all,+net_raw",
        "--ambient-caps=-all,+net_raw",
        "--no-new-privs",
        session.python,
        "-I",
        "-m",
        MODULE,
    ]


def trusted_pkexec():
    path = Path("/usr/bin/pkexec")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("OS_AUTH_BINARY_UNTRUSTED")
    return str(path)


class OSAuthentication:
    def __init__(self, *, launcher=None, inspector=None, binary=None):
        self.launcher = launcher or asyncio.create_subprocess_exec
        self.inspector = inspector or support
        self.binary = binary or trusted_pkexec
        self.process = self.task = None
        self.state = "NOT_REQUESTED"
        self.exit_code = None
        self.error = None
        self.cancel_requested = False

    async def start(self, owner, approved_sha):
        if self.task is not None and not self.task.done():
            raise ValueError("OS_AUTH_ALREADY_PENDING")
        assessment = self.inspector()
        if assessment["status"] != "OS_AUTH_UI_AVAILABLE_UNTESTED":
            self.state = "OS_AUTH_UI_UNAVAILABLE"
            return assessment
        if owner.command(str(owner.session.session_id)).get("listener_ready") is not True:
            raise ValueError("OS_AUTH_CURRENT_LISTENER_REQUIRED")
        session = load(owner.directory)
        if session != owner.session:
            raise ValueError("OS_AUTH_SESSION_POLICY_CHANGED")
        if approved_sha != session.code_sha256["stream_helper.py"]:
            raise ValueError("NEW_STREAM_HELPER_EXPLICIT_APPROVAL_REQUIRED")
        pkexec = self.binary()
        self.state = "AUTHENTICATING"
        self.error = None
        self.exit_code = None
        self.cancel_requested = False
        owner.store.runtime.event(
            "STREAM_OS_AUTH_REQUESTED",
            dict(
                helper_sha256=approved_sha, session=str(session.session_id), password_received=False
            ),
        )
        env = {"PATH": os.defpath, "LANG": "C.UTF-8"}
        for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if key in os.environ:
                env[key] = os.environ[key]
        try:
            self.process = await self.launcher(
                str(pkexec),
                *arguments(session),
                "--directory",
                str(owner.directory),
                "--session-digest",
                digest(session.model_dump(mode="json")),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL,
                env=env,
            )
        except OSError:
            self.state = "AUTH_UNKNOWN"
            self.error = "OS_AUTH_LAUNCH_FAILED"
            owner.store.runtime.event("STREAM_OS_AUTH_FAILURE", {"error": self.error})
            await owner.stop(abort=True)
            return self.snapshot()
        self.task = asyncio.create_task(self._watch(owner, session.session_id, owner.capture))
        return dict(
            status="AUTHENTICATING",
            password_handled_by="OS_ONLY",
            operational_gate="OPERATIONAL_INFERENCE_BLOCKED",
        )

    async def _watch(self, owner, session_id, capture):
        started = asyncio.get_running_loop().time()
        waiter = asyncio.create_task(self.process.wait())
        try:
            while self.process.returncode is None:
                if capture.ready is not None:
                    self.state = "HELPER_RUNNING"
                elif asyncio.get_running_loop().time() - started > 60:
                    self.error = "OS_AUTH_DEADLINE_EXCEEDED"
                    await self.cancel()
                    if owner.session.session_id == session_id:
                        await owner.stop(abort=True)
                    return
                try:
                    await asyncio.wait_for(asyncio.shield(waiter), 0.2)
                except TimeoutError:
                    continue
            self.exit_code = self.process.returncode
            self.state = (
                "HELPER_EXITED"
                if self.exit_code == 0
                else "AUTH_CANCELLED"
                if self.exit_code == 126
                else "AUTH_DENIED"
                if self.exit_code == 127
                else "HELPER_FAILED"
            )
            if self.cancel_requested:
                self.state = "AUTH_CANCELLED"
            if not self.cancel_requested and self.exit_code == 0 and capture.ready is None:
                self.state = "HELPER_EXIT_WITHOUT_READY"
            owner.store.runtime.event(
                "STREAM_OS_AUTH_EXIT", dict(status=self.state, exit_code=self.exit_code)
            )
            if self.exit_code != 0 or capture.ready is None:
                self.error = self.state
                if owner.session.session_id == session_id:
                    await owner.stop(abort=True)
        except (OSError, ValueError):
            self.state = "AUTH_UNKNOWN"
            self.error = "OS_AUTH_LAUNCH_OR_SUPERVISION_FAILED"
            if owner.session.session_id == session_id:
                await owner.stop(abort=True)
        finally:
            if not waiter.done():
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)

    async def cancel(self):
        process = self.process
        if process is None:
            return
        if process.returncode is not None and (self.task is None or self.task.done()):
            return
        self.cancel_requested = True
        if process is not None and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), 3)
            except (OSError, TimeoutError):
                self.error = "OS_AUTH_CANCELLATION_UNCERTAIN"
        if self.task is not None and self.task is not asyncio.current_task():
            try:
                await asyncio.wait_for(asyncio.shield(self.task), 4)
            except TimeoutError:
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
                self.error = "OS_AUTH_CANCELLATION_UNCERTAIN"
        self.state = (
            "AUTH_UNKNOWN" if self.error == "OS_AUTH_CANCELLATION_UNCERTAIN" else "AUTH_CANCELLED"
        )

    def snapshot(self):
        return {
            **self.inspector(),
            "state": self.state,
            "last_error": self.error,
            "helper_exit_code": self.exit_code,
        }
