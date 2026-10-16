"""Terminal owns sudo authentication; GUI only launches a reviewed noninteractive child."""

import asyncio
import stat
from pathlib import Path

from soc_agent.security_ai.operational.network_capture import total_session
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_auth import OSAuthentication, arguments


def sudo_binary():
    path = Path("/usr/bin/sudo")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("TOTAL_AUTH_BINARY_UNTRUSTED")
    return str(path)


class TerminalAuthentication(OSAuthentication):
    def __init__(self, *, launcher=None):
        super().__init__(
            launcher=launcher,
            inspector=lambda: {
                "status": "TERMINAL_AUTH_REQUIRED",
                "password_handled_by": "OS_TERMINAL_ONLY",
            },
        )

    async def start(self, owner, approved_sha):
        if self.task is not None and not self.task.done():
            raise ValueError("OS_AUTH_ALREADY_PENDING")
        if owner.command(str(owner.session.session_id)).get("listener_ready") is not True:
            raise ValueError("OS_AUTH_CURRENT_LISTENER_REQUIRED")
        session = total_session.load(owner.directory)
        if session != owner.session or approved_sha != session.code_sha256["total_helper.py"]:
            raise ValueError("NEW_TOTAL_HELPER_EXPLICIT_APPROVAL_REQUIRED")
        argv = arguments(session)
        argv[-1] = total_session.MODULE
        self.state = "AUTHENTICATING"
        self.error = self.exit_code = None
        self.cancel_requested = False
        owner.store.runtime.event(
            "TOTAL_TERMINAL_AUTH_HANDOFF",
            {
                "helper_sha256": approved_sha,
                "password_received": False,
                "session_digest": digest(session.model_dump(mode="json")),
            },
        )
        try:
            self.process = await self.launcher(
                sudo_binary(),
                "-n",
                *argv,
                "--directory",
                str(owner.directory),
                "--session-digest",
                digest(session.model_dump(mode="json")),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
        except OSError:
            self.state, self.error = "AUTH_DENIED", "TOTAL_AUTH_UNAVAILABLE_OR_EXPIRED"
            owner.store.runtime.event("TOTAL_AUTH_FAILURE", {"error": self.error})
            await owner.stop(abort=True)
            return self.snapshot()
        self.task = asyncio.create_task(self._watch(owner, session.session_id, owner.capture))
        return {"status": "AUTHENTICATING", "password_handled_by": "OS_TERMINAL_ONLY"}

    async def _watch(self, owner, session_id, capture):
        await super()._watch(owner, session_id, capture)
        if self.exit_code == 1 and capture.ready is None and not self.cancel_requested:
            # sudo -n expiry and early helper failure cannot be separated without
            # trustworthy evidence; do not retain arbitrary stderr/credentials.
            self.state = self.error = "AUTH_EXPIRED_OR_HELPER_START_FAILED"
            owner.store.runtime.event(
                "TOTAL_AUTH_OR_START_FAILURE",
                {
                    "error": self.error,
                    "root_cause": "UNKNOWN",
                    "automatic_retry": False,
                },
            )
