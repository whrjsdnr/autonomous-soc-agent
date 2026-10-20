"""Separate OS-authentication-only session. Never load/attach or grant Kernel authority."""

import fcntl
import hashlib
import os
import select
import stat
import struct
import subprocess
import time

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.installation import validate_root_release
from soc_agent.security_ai.ebpf_tc.os_handoff import Handoff


def open_authentication_tty(uid: int) -> int:
    """Match owned terminal input to the kernel's controlling terminal, by FD.

    /dev/tty is a root-owned alias, not the user's actual PTY inode. Linux
    TIOCGDEV returns the real terminal device even through that alias. Require
    a matching owned stdin terminal and foreground process group as well.
    """
    tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    input_fd = -1
    try:
        input_fd = os.dup(0)
        terminal = os.fstat(input_fd)
        # Linux asm-generic/ioctls.h: _IOR('T', 0x32, unsigned int).
        encoded = struct.unpack("=I", fcntl.ioctl(tty, 0x80045432, bytes(4)))[0]
        actual_device = os.makedev(
            (encoded >> 8) & 0xFFF, (encoded & 0xFF) | ((encoded >> 12) & 0xFFF00)
        )
        if (
            not os.isatty(tty)
            or not os.isatty(input_fd)
            or not stat.S_ISCHR(terminal.st_mode)
            or terminal.st_uid != uid
            or terminal.st_rdev != actual_device
            or os.tcgetpgrp(tty) != os.getpgrp()
            or os.tcgetpgrp(input_fd) != os.getpgrp()
        ):
            raise ValueError("AUTH_QUALIFICATION_TTY_REQUIRED")
        return tty
    except BaseException:
        os.close(tty)
        raise
    finally:
        if input_fd >= 0:
            os.close(input_fd)


class AuthenticationQualification(Handoff):
    purpose_label = b"SOC_AUTH_ONLY_V1\0"
    entry_mode = "--auth-qualification"
    native_origin = "OS_AUTH_ONLY_NATIVE_NO_KERNEL"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.qualification_only = True

    @property
    def approval(self) -> str:
        return hashlib.sha256(self.purpose_label + self.envelope).hexdigest()

    def sudo_command(self) -> tuple[str, ...]:
        return (
            "/usr/bin/sudo",
            "-k",
            "-u",
            "root",
            "--",
            "/usr/libexec/soc-agent-ebpf/bootstrap",
            self.entry_mode,
            str(self.plan.broker.uid),
            str(self.plan.broker.gid),
            self.plan.broker.application.application_session.hex,
            self.envelope[-32:].hex(),
            self.release.identity,
            self.approval,
        )

    def authenticate_native(self) -> dict:
        if self.state != "AUTHENTICATION_REQUIRED" or self.attempted or self.ended:
            raise ValueError("AUTH_QUALIFICATION_REPLAY")
        self._scope()
        validate_root_release(self.release)
        tty = open_authentication_tty(self.plan.broker.uid)
        try:
            self.attempted = True
            self.origin = self.native_origin
            self.state, self.authentication = "AUTHENTICATING", "OS_AUTH_PENDING"
            self._event("OS_AUTH_REQUESTED", kernel_actions_allowed=not self.qualification_only)
            self.child = subprocess.Popen(
                self.sudo_command(),
                stdin=tty,
                stdout=tty,
                stderr=tty,
                close_fds=True,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
            self.listener.settimeout(5)
            deadline = time.monotonic() + 60
            while not select.select([self.listener], [], [], 0.1)[0]:
                if self.child.poll() is not None:
                    raise ValueError("AUTH_QUALIFICATION_ENTRY_REJECTED")
                if time.monotonic() >= deadline:
                    # Cancel this invocation only. Never retry authentication.
                    try:
                        self.child.terminate()
                    except PermissionError:
                        self.error = "AUTH_CANCELLATION_UNVERIFIED"
                    raise ValueError("AUTH_QUALIFICATION_TIMEOUT")
            self._bind(fixture=False)
            from pathlib import Path

            status = Path(f"/proc/{self.identity.pid}/status").read_text()
            names = {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}
            self.process_caps = {
                name: int(value.strip(), 16)
                for row in status.splitlines()
                if ":" in row
                for name, value in [row.split(":", 1)]
                if name in names
            }
            expected = {name: 0 for name in names}
            if not self.qualification_only:
                expected["CapPrm"] = expected["CapBnd"] = (1 << 39) | (1 << 12)
            if self.process_caps != expected:
                raise ValueError("QUALIFICATION_CAPABILITY_SCOPE_MISMATCH")
            self._event("QUALIFICATION_CAPABILITIES_OBSERVED", capability_sets=self.process_caps)
            self._event(
                "OS_AUTH_QUALIFICATION_VERIFIED", kernel_actions_allowed=not self.qualification_only
            )
        except (OSError, ValueError, EOFError, KeyboardInterrupt):
            self._reject("AUTH_QUALIFICATION_FAILED")
            raise
        finally:
            os.close(tty)
        return self.snapshot()

    def close(self) -> dict:
        if self.ended:
            return self.snapshot()
        if self.state == "BROKER_READY" and not self.error:
            try:
                self.command(
                    Command(
                        command="STOP",
                        plan_digest=self.plan.approval,
                        sequence=self.sequence + 1,
                        reason="USER_STOP",
                    )
                )
            except (OSError, ValueError, EOFError):
                self.error = self.error or "AUTH_QUALIFICATION_STOP_UNVERIFIED"
        self.ended, self.deadline = True, None
        if self.channel:
            self.channel.close()
            self.channel = None
        if self.listener:
            self.listener.close()
            self.listener = None
        self.data.close()
        if self.audit_fd >= 0:
            os.close(self.audit_fd)
            self.audit_fd = -1
        if self.child:
            try:
                self.child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.error = "AUTH_QUALIFICATION_EXIT_UNVERIFIED"
        self.authentication = "REVOKED"
        self.cleanup = (
            "AUTH_ONLY_PROCESS_EXIT_VERIFIED"
            if self.child and self.child.returncode == 0 and not self.error
            else "CLEANUP_UNVERIFIED"
        )
        self.state = "CLOSED" if not self.error else "ERROR"
        self._event("AUTH_QUALIFICATION_CLOSED", cleanup=self.cleanup, kernel_actions_allowed=False)
        return self.snapshot()

    def snapshot(self) -> dict:
        result = super().snapshot()
        result["qualification_purpose"] = self.entry_mode
        result["observed_capability_sets"] = getattr(self, "process_caps", None)
        return result

    def authenticate_fixture(self, *args, **kwargs):
        raise ValueError("AUTH_QUALIFICATION_NATIVE_ONLY_NO_FIXTURE_IMPERSONATION")


class LiveQualification(AuthenticationQualification):
    """Explicit scoped research capture; Native AI and operational release stay closed."""

    purpose_label = b"SOC_TCX_LIVE_V1\0"
    entry_mode = "--live-qualification"
    native_origin = "TCX_LIVE_QUALIFICATION_NATIVE"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.plan.broker.application.scope.hook != "INGRESS":
            raise ValueError("TCX_QUALIFICATION_INGRESS_ONLY")
        self.qualification_only = False

    def close(self) -> dict:
        return Handoff.close(self)
