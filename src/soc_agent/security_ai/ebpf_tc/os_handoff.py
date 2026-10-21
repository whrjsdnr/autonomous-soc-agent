"""One-shot OS-to-Broker rendezvous. No sudo invocation or Native admission in B-2J.

The real C entry receives the same envelope/FD protocol after OS authentication.
Only the explicitly named ordinary-UID transport fixture may be spawned here.
"""

import array
import hashlib
import os
import select
import socket
import struct
import subprocess
import time
from collections import deque
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.contracts import (
    RunIdentity,
    alive,
    local_controller,
    process_identity,
)
from soc_agent.security_ai.ebpf_tc.contracts import OWNER, NativePlan, request
from soc_agent.security_ai.ebpf_tc.data_plane import PacketChannel
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest, verify_package
from soc_agent.security_ai.ebpf_tc.journal import KINDS, TCX_KINDS, TCX_OWNER, recover_native
from soc_agent.security_ai.ebpf_tc.trust import release_approval
from soc_agent.security_ai.research.models import Frozen, digest

CREDENTIAL = struct.Struct("3i")
HELLO = struct.Struct("<6IQ32s32s")
REPLY = struct.Struct("<IIiI56s")
MAGIC = 0x4A324253


class AuthenticationFixture(Frozen):
    source: Literal["MOCK_OS_POLICY_NOT_NATIVE"] = "MOCK_OS_POLICY_NOT_NATIVE"
    tty: bool = Field(default=True, strict=True)
    password_required: bool = Field(default=True, strict=True)
    cache_bypassed: bool = Field(default=True, strict=True)
    nopasswd: bool = Field(default=False, strict=True)
    account_allowed: bool = Field(default=True, strict=True)
    outcome: Literal["SUCCESS", "FAILURE", "CANCELLED", "TIMEOUT"] = "SUCCESS"

    def validate_contract(self) -> None:
        if not (
            self.tty
            and self.password_required
            and self.cache_bypassed
            and not self.nopasswd
            and self.account_allowed
            and self.outcome == "SUCCESS"
        ):
            raise ValueError("OS_PASSWORD_CONTRACT_BLOCKED")


class Handoff:
    def __init__(
        self,
        application: Application,
        plan: NativePlan,
        package: Path,
        manifest_sha: str,
        artifacts: Path,
    ):
        self.application, self.plan = application, plan
        self.package, self.artifacts = package, artifacts
        self.release: ReleaseManifest = verify_package(package, manifest_sha)
        self.envelope = release_approval(plan, self.release)
        self.envelope_sha = hashlib.sha256(self.envelope).digest()
        self._approval = self.envelope[-32:].hex()
        if (
            application.store is None
            or application.plan.application_session != plan.broker.application.application_session
            or plan.broker.application.controller != local_controller()
        ):
            raise ValueError("HANDOFF_APPLICATION_IDENTITY")
        self.listener: socket.socket | None = None
        self.channel: socket.socket | None = None
        self.child: subprocess.Popen | None = None
        self.identity = None
        self.sequence = 0
        self.notifications = 0
        self.deadline: float | None = None
        self.rate: deque[float] = deque(maxlen=32)
        self.attempted = self.ended = False
        self.state, self.authentication = "NOT_PREPARED", "REQUIRED"
        self.cleanup = "NOT_OBSERVED"
        self.broker_error = None
        self.loader_diagnostics = []
        self.verifier_log = None
        self.fd_release_evidence = []
        self.error: str | None = None
        self.origin = "NATIVE_PENDING_NOT_EXECUTED"
        self.qualification_only = False
        self.collector_state = "NOT_OBSERVED"
        self.link_evidence = None
        self.audit_path = application.directory / "os-handoff-journal.bin"
        self.audit_fd = -1
        # Transport binds the sealed envelope digest, not the separately displayed
        # auth-only/live purpose approval. Both are checked at the root entry.
        self.data = PacketChannel(plan, self.envelope[-32:].hex(), application.directory)

    def _event(self, kind: str, **details) -> None:
        self.application._event(
            kind,
            handoff_source=self.origin,
            handoff_session=str(self.plan.broker.application.application_session),
            release_manifest_digest=self.release.identity,
            handoff_approval_digest=self.envelope[-32:].hex(),
            **details,
        )

    def _scope(self) -> None:
        controller = self.plan.broker.application.controller
        if not alive(controller) or controller != local_controller():
            raise ValueError("HANDOFF_CONTROLLER_IDENTITY")
        scope = self.plan.broker.application.scope
        if (
            os.readlink("/proc/self/ns/net") != scope.net_namespace
            or socket.if_nametoindex(scope.interface) != scope.ifindex
        ):
            raise ValueError("HANDOFF_SCOPE_CHANGED")
        if verify_package(self.package, self.release.identity) != self.release:
            raise ValueError("HANDOFF_RELEASE_CHANGED")

    def prepare(self) -> dict:
        if self.state != "NOT_PREPARED":
            raise ValueError("HANDOFF_SESSION_REUSE")
        self._scope()
        # Persistent audit is a replay *denial*, never a restorable grant.
        with self.application.store.database.transaction(write=False) as db:
            import json

            rows = db.execute("SELECT payload FROM monitor_audit").fetchall()
        if any(
            json.loads(row[0])["kind"] == "APP_SESSION_PREPARED"
            and json.loads(row[0])["details"].get("handoff_session")
            == str(self.plan.broker.application.application_session)
            for row in rows
        ):
            raise ValueError("HANDOFF_SESSION_REPLAY")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.settimeout(5)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        uid = self.plan.broker.uid
        session = self.plan.broker.application.application_session.hex
        try:
            listener.bind(f"\0soc-ebpf.{uid}.{session}")
            listener.listen(1)
            self.data.listen()
            self._event("APP_SESSION_PREPARED")
        except BaseException:
            listener.close()
            raise
        self.listener = listener
        self.state = "APPROVAL_REQUIRED"
        return self.snapshot()

    @property
    def approval(self) -> str:
        return self._approval

    def approve(self, approval: str) -> None:
        if self.state != "APPROVAL_REQUIRED" or approval != self.approval:
            raise ValueError("HANDOFF_APPROVAL_MISMATCH")
        self._scope()
        self._event("APPROVAL_ACCEPTED", scope="OS_HANDOFF_CONTRACT_NATIVE_GATE_CLOSED")
        self.state = "AUTHENTICATION_REQUIRED"

    def sudo_command(self) -> tuple[str, ...]:
        """Display only. -k with a command ignores cache without a global -K purge.

        Neither this argv nor sudo exit success proves a password challenge. The
        independent C OS-policy gate stays closed; Native auth is not invoked.
        """
        return (
            "/usr/bin/sudo",
            "-k",
            "-u",
            "root",
            "--",
            "/usr/libexec/soc-agent-ebpf/bootstrap",
            "--os-handoff",
            str(self.plan.broker.uid),
            str(self.plan.broker.gid),
            self.plan.broker.application.application_session.hex,
            self.approval,
            self.release.identity,
        )

    def authenticate_native(self) -> dict:
        # No currently representable release can pass this phase boundary. The C
        # entry additionally denies OS auth qualification and Kernel operations.
        if self.release.native_release == "BLOCKED":
            raise ValueError("B2J_NATIVE_OS_AUTH_QUALIFICATION_PENDING")
        if self.state != "AUTHENTICATION_REQUIRED" or self.attempted or self.ended:
            raise ValueError("HANDOFF_AUTHENTICATION_REPLAY")
        from soc_agent.security_ai.ebpf_tc.installation import validate_root_release

        self._scope()
        validate_root_release(self.release)
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        try:
            if (
                not os.isatty(tty)
                or os.fstat(tty).st_uid != self.plan.broker.uid
                or os.tcgetpgrp(tty) != os.getpgrp()
            ):
                raise ValueError("HANDOFF_OS_TERMINAL_REQUIRED")
            self.attempted = True
            self.state, self.authentication = "AUTHENTICATING", "OS_AUTH_PENDING"
            self.origin = "B2J_OS_AUTH_NATIVE"
            self._event("OS_AUTH_REQUESTED", invoked=True)
            # OS owns the terminal conversation. No -S, -A, password pipe,
            # preserve-env, shell, extra descriptors or user executable path.
            self.child = subprocess.Popen(
                self.sudo_command(),
                stdin=tty,
                stdout=tty,
                stderr=tty,
                close_fds=True,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
            self.listener.settimeout(60)  # authentication wait is not Capture time
            self._bind(fixture=False)
        except (OSError, ValueError, EOFError):
            self._reject("HANDOFF_OS_AUTHENTICATION_FAILED")
            raise
        except KeyboardInterrupt:
            self._reject("HANDOFF_OS_AUTHENTICATION_CANCELLED")
            raise
        finally:
            os.close(tty)
        return self.snapshot()

    def authenticate_fixture(
        self, facts: AuthenticationFixture, *, packets: tuple[bytes, ...] = ()
    ) -> dict:
        if self.state != "AUTHENTICATION_REQUIRED" or self.attempted or self.ended:
            raise ValueError("HANDOFF_AUTHENTICATION_REPLAY")
        self.attempted = True
        self.origin = "B2J_TRANSPORT_FIXTURE_NOT_OS_AUTH"
        self.state, self.authentication = "AUTHENTICATING", "MOCK_PENDING"
        self._event("OS_AUTH_REQUESTED", invoked=False)
        try:
            facts.validate_contract()
            self._scope()
            if len(packets) > 4096 or any(len(p) != 80 for p in packets):
                raise ValueError("TCX_PACKET_FIXTURE_BOUND")
            target = self.artifacts / (
                "packet-handoff-fixture" if packets else "os-handoff-fixture"
            )
            # Fixed test-only target, ordinary UID, never a sudo/Root fallback.
            import tempfile

            from soc_agent.security_ai.ebpf_tc.build import compile_native

            with tempfile.TemporaryDirectory(prefix="soc-handoff-reference-") as temporary:
                compile_native(Path(temporary))
                reference = (Path(temporary) / target.name).read_bytes()
            if read_held(target.absolute(), owner=os.getuid(), limit=1048576) != reference:
                raise ValueError("HANDOFF_FIXTURE_IDENTITY")
            executable = os.memfd_create(
                "soc-unprivileged-handoff-fixture", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
            )
            events = -1
            try:
                import fcntl

                if packets:
                    events = os.memfd_create(
                        "soc-packet-fixture", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
                    )
                    body = b"".join(packets)
                    if os.write(events, body) != len(body):
                        raise ValueError("TCX_PACKET_FIXTURE_WRITE")
                    fcntl.fcntl(events, 1033, 15)
                if os.write(executable, reference) != len(reference):
                    raise ValueError("HANDOFF_EXECUTABLE_WRITE")
                fcntl.fcntl(executable, 1033, 15)
                self.child = subprocess.Popen(
                    [
                        f"/proc/self/fd/{executable}",
                        self.plan.broker.application.application_session.hex,
                        self.approval,
                        self.release.identity,
                    ]
                    + ([str(events)] if events >= 0 else []),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    pass_fds=(executable,) + ((events,) if events >= 0 else ()),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                )
            finally:
                os.close(executable)
                if events >= 0:
                    os.close(events)
            self._bind(fixture=True)
        except (OSError, ValueError, EOFError):
            self._reject("HANDOFF_AUTHENTICATION_FAILED")
            raise
        except KeyboardInterrupt:
            self._reject("HANDOFF_AUTHENTICATION_CANCELLED")
            raise
        return self.snapshot()

    def _bind(self, *, fixture: bool) -> None:
        if self.listener is None:
            raise ValueError("HANDOFF_LISTENER_REQUIRED")
        self.channel, _ = self.listener.accept()
        self.channel.settimeout(5)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.listener.close()
        self.listener = None
        pid, uid, gid = CREDENTIAL.unpack(
            self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, CREDENTIAL.size)
        )
        expected_uid = self.plan.broker.uid if fixture else 0
        expected_gid = self.plan.broker.gid if fixture else 0
        if (
            (uid, gid) != (expected_uid, expected_gid)
            or fixture
            and (self.child is None or pid != self.child.pid)
        ):
            raise ValueError("HANDOFF_PEER_CREDENTIALS")
        self.identity = process_identity(pid)
        if self.identity.uid != expected_uid:
            raise ValueError("HANDOFF_PROCESS_IDENTITY")
        import fcntl

        fd = os.memfd_create("soc-untrusted-approval", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            if os.write(fd, self.envelope) != len(self.envelope):
                raise ValueError("HANDOFF_PLAN_WRITE")
            fcntl.fcntl(fd, 1033, 15)
            self.audit_fd = os.open(
                self.audit_path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_APPEND | os.O_CLOEXEC,
                0o600,
            )
            descriptors = array.array("i", (fd, self.audit_fd))
            if self.channel.sendmsg(
                [self.envelope], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]
            ) != len(self.envelope):
                raise ValueError("HANDOFF_SEND_BOUND")
        finally:
            os.close(fd)
        self._hello(1, fixture)
        self._event("OS_AUTH_HANDOFF_VERIFIED", verified_scope="FIXTURE" if fixture else "OS")
        self._hello(2, fixture)
        if not self.qualification_only:
            self.data.bind(self.identity, fixture=fixture)
        self._event("TCX_DATA_CHANNEL_BOUND", data=self.data.snapshot())
        self._scope()
        self.deadline = time.monotonic() + 3600
        self.authentication = "MOCK_VERIFIED_NOT_NATIVE" if fixture else "OS_AUTHENTICATED"
        self.state = "BROKER_READY"
        self._event("BROKER_SESSION_BOUND", broker_pid=pid, broker_ticks=self.identity.start_ticks)
        self._event("BROKER_READY")

    def _packet(self, *, uid: int, gid: int) -> bytes:
        if self.channel is None or self.identity is None:
            raise ValueError("HANDOFF_CHANNEL_REQUIRED")
        deadline = time.monotonic() + 5
        while True:
            if self.data.error:
                raise ValueError("HANDOFF_DATA_INTEGRITY_FAILED")
            if select.select([self.channel], [], [], min(0.1, max(0, deadline - time.monotonic())))[
                0
            ]:
                break
            if time.monotonic() >= deadline:
                raise ValueError("HANDOFF_CONTROL_TIMEOUT")
        body, ancillary, flags, _ = self.channel.recvmsg(
            4096, socket.CMSG_SPACE(4 * CREDENTIAL.size), socket.MSG_CMSG_CLOEXEC
        )
        credential = None
        invalid = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array("i")
                received.frombytes(data[: len(data) - len(data) % received.itemsize])
                for fd in received:
                    os.close(fd)
                invalid = True
                continue
            if level != socket.SOL_SOCKET or kind != socket.SCM_CREDENTIALS or credential:
                invalid = True
                continue
            if len(data) != CREDENTIAL.size:
                invalid = True
                continue
            credential = CREDENTIAL.unpack(data)
        if not body:
            raise EOFError("HANDOFF_BROKER_EOF")
        current = process_identity(self.identity.pid)
        if (
            invalid
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or credential != (self.identity.pid, uid, gid)
            or current.start_ticks != self.identity.start_ticks
            or current.uid not in ({0, self.plan.broker.uid} if uid == 0 else {uid})
        ):
            raise ValueError("HANDOFF_PEER_IDENTITY_CHANGED")
        return body

    def _next(self, *, uid: int, gid: int) -> bytes:
        for _ in range(32):
            body = self._packet(uid=uid, gid=gid)
            if len(body) not in (192, 240):
                return body
            kind = body[32:64].split(b"\0", 1)[0].decode("ascii")
            if (
                body[:32].hex() != self.plan.approval
                or kind not in KINDS | TCX_KINDS
                or hashlib.sha256(body[:-32]).digest() != body[-32:]
            ):
                raise ValueError("HANDOFF_JOURNAL_NOTIFICATION")
            if kind in {"TCX_LINK_VERIFIED", "TCX_LINK_RELEASED", "TCX_CLEANUP_UNVERIFIED"}:
                row = TCX_OWNER.unpack_from(body, 64)
                if (
                    row[1] != int(self.plan.broker.application.scope.net_namespace[5:-1])
                    or row[11].hex() != self.plan.program_sha256
                ):
                    raise ValueError("HANDOFF_LINK_EVIDENCE_SCOPE")
                self.link_evidence = dict(
                    state=kind,
                    generation=row[0],
                    namespace_inode=row[1],
                    link_id=row[3],
                    program_id=row[4],
                    ifindex=row[5],
                    attach_type=row[6],
                    program_tag=row[9].hex(),
                    pinned=bool(row[8]),
                )
            self.notifications += 1
            if self.notifications > 1024:
                raise ValueError("HANDOFF_NOTIFICATION_BUDGET")
        raise ValueError("HANDOFF_NOTIFICATION_BACKPRESSURE")

    def _hello(self, phase: int, fixture: bool) -> None:
        uid = self.plan.broker.uid if fixture or phase == 2 else 0
        gid = self.plan.broker.gid if fixture or phase == 2 else 0
        body = self._next(uid=uid, gid=gid)
        if len(body) != HELLO.size:
            raise ValueError("HANDOFF_READY_SCHEMA")
        magic, stage, source, pid, claimed_uid, claimed_gid, ticks, envelope, broker = HELLO.unpack(
            body
        )
        if (
            (magic, stage, source)
            != (MAGIC, phase, 3 if self.qualification_only else 2 if fixture else 1)
            or (pid, claimed_uid, claimed_gid, ticks)
            != (self.identity.pid, uid, gid, self.identity.start_ticks)
            or envelope != self.envelope_sha
            or broker.hex()
            != (
                self.plan.bootstrap_sha256
                if self.qualification_only
                else self.plan.native_broker_sha256
            )
        ):
            raise ValueError("HANDOFF_READY_IDENTITY")

    def validate_run_identity(self, run: RunIdentity) -> None:
        """Check the same bound run before authentication and before sending IPC."""
        if (
            run.application_session != self.plan.broker.application.application_session
            or run.scope_digest
            != digest(self.plan.broker.application.scope.model_dump(mode="json"))
        ):
            raise ValueError("HANDOFF_RUN_SCOPE")

    def command(self, value: Command) -> dict:
        if self.qualification_only and value.command not in {"STATUS", "STOP"}:
            raise ValueError("AUTH_QUALIFICATION_NO_KERNEL_ACTION")
        if self.state != "BROKER_READY" or self.ended or self.deadline is None:
            raise ValueError("HANDOFF_SESSION_NOT_READY")
        try:
            if time.monotonic() >= self.deadline:
                self._event("BROKER_SESSION_EXPIRED")
                raise ValueError("HANDOFF_APPLICATION_EXPIRED")
            self._scope()
            if value.plan_digest != self.plan.approval or value.sequence != self.sequence + 1:
                raise ValueError("HANDOFF_COMMAND_REPLAY_OR_SCOPE")
            if value.run:
                self.validate_run_identity(value.run)
            now = time.monotonic()
            while self.rate and now - self.rate[0] >= 1:
                self.rate.popleft()
            if len(self.rate) >= 32:
                raise ValueError("HANDOFF_RATE_LIMIT")
            self.rate.append(now)
            wire = request(value)
            if value.command == "ATTACH":
                self.data.prepare_adapter(int.from_bytes(value.run.generation.bytes[:8], "little"))
            if self.channel.send(wire) != len(wire):
                raise ValueError("HANDOFF_REQUEST_BOUND")
            body = self._next(uid=self.plan.broker.uid, gid=self.plan.broker.gid)
            if len(body) != REPLY.size:
                raise ValueError("HANDOFF_REPLY_SCHEMA")
            seq, state, error, reserved, owner = REPLY.unpack(body)
            if seq != value.sequence or reserved or state not in (3, 4):
                raise ValueError("HANDOFF_REPLY_SCHEMA")
            if error:
                self.broker_error = dict(operation=value.command, sequence=seq, return_value=error)
                self._event("BROKER_COMMAND_REJECTED", **self.broker_error)
                raise ValueError(f"HANDOFF_BROKER_REQUEST_DENIED:{error}")
            self.data.pump()
            self.collector_state = "ACTIVE" if state == 4 else "STOPPED"
            self.sequence = seq
            return {
                "source": self.origin,
                "state": state,
                "owner_observed": owner != bytes(OWNER.size),
            }
        except (OSError, ValueError, EOFError):
            self._reject("HANDOFF_COMMAND_FAILED")
            raise

    def stop(self) -> dict:
        if self.state == "BROKER_READY" and not self.ended:
            self.command(
                Command(
                    command="STOP",
                    plan_digest=self.plan.approval,
                    sequence=self.sequence + 1,
                    reason="USER_STOP",
                )
            )
        return self.snapshot()

    def approval_scope(self) -> dict:
        scope = self.plan.broker.application.scope
        return {
            "session_id": str(self.plan.broker.application.application_session),
            "release_manifest_digest": self.release.identity,
            "bootstrap_sha256": self.plan.bootstrap_sha256,
            "broker_sha256": self.plan.native_broker_sha256,
            "loader_sha256": self.plan.loader_sha256,
            "program_sha256": self.plan.program_sha256,
            "bundle_digest": self.plan.bundle_digest,
            "interface": scope.interface,
            "ifindex": scope.ifindex,
            "namespace": scope.net_namespace,
            "hook": scope.hook,
            "duration_seconds": self.release.duration_seconds,
            "metadata_events": self.release.events,
            "broker_address_space_mib": self.release.broker_address_space_mib,
            "cpu_seconds": self.release.cpu_seconds,
            "queue": self.release.queue_capacity,
            "application_seconds": self.release.application_seconds,
            "approval_digest": self.approval,
            "native_gate": "BLOCKED",
        }

    def observe(self) -> dict:
        if self.state == "BROKER_READY" and not self.ended:
            try:
                self.command(
                    Command(
                        command="STATUS", plan_digest=self.plan.approval, sequence=self.sequence + 1
                    )
                )
            except (OSError, ValueError, EOFError):
                # command has already recorded failure and revoked the session.
                return self.snapshot()
        return self.snapshot()

    def _reject(self, code: str) -> None:
        self.error = code
        self.state, self.authentication = "ERROR", "REVOKED"
        try:
            self._event("HANDOFF_REJECTED", code=code)
        finally:
            self.close()

    def close(self) -> dict:
        if self.ended:
            return self.snapshot()
        if self.state == "BROKER_READY" and self.error is None:
            try:
                self.command(
                    Command(
                        command="CLEANUP",
                        plan_digest=self.plan.approval,
                        sequence=self.sequence + 1,
                    )
                )
            except (OSError, ValueError, EOFError):
                # command already revoked authority and closed the connection.
                return self.snapshot()
        self.ended = True
        self.deadline = None
        self.authentication = "REVOKED"
        if self.listener:
            self.listener.close()
            self.listener = None
        if self.channel:
            self.channel.close()
            self.channel = None
        if self.child:
            try:
                self.child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                if self.origin != "B2J_TRANSPORT_FIXTURE_NOT_OS_AUTH":
                    self.error = "HANDOFF_NATIVE_EXIT_UNVERIFIED"
                    self.child = None
                else:
                    self._terminate_fixture()
        try:
            self.data.close()
        except (OSError, ValueError):
            self.error = self.error or "HANDOFF_DATA_FINALIZATION_UNVERIFIED"
        if self.audit_fd >= 0:
            os.close(self.audit_fd)
            self.audit_fd = -1
        self.cleanup = "CLEANUP_UNVERIFIED"
        if self.audit_path.exists():
            try:
                evidence = recover_native(self.audit_path, self.plan.approval)
                self.loader_diagnostics = evidence["loader_diagnostics"]
                self.verifier_log = evidence["verifier_log"]
                self.fd_release_evidence = evidence["fd_release_evidence"]
                if self.link_evidence and evidence["last_link_lifecycle"] in {
                    "TCX_LINK_RELEASED",
                    "TCX_CLEANUP_VERIFIED",
                }:
                    self.link_evidence["state"] = evidence["last_link_lifecycle"]
                if evidence["claimed_cleanup"] and self.child and self.child.returncode == 0:
                    self.cleanup = (
                        "FIXTURE_VERIFIED"
                        if self.origin == "B2J_TRANSPORT_FIXTURE_NOT_OS_AUTH"
                        else "PROCESS_AND_AUDIT_VERIFIED"
                    )
            except (ValueError, OSError):
                self.cleanup = "CLEANUP_UNVERIFIED"
                self.error = self.error or "HANDOFF_JOURNAL_UNVERIFIED"
        self.authentication = "REVOKED"
        self.collector_state = (
            "STOPPED" if self.child and self.child.returncode is not None else "UNKNOWN"
        )
        self.state = (
            "ERROR"
            if self.error
            else "CLEANUP_UNVERIFIED"
            if self.child and self.cleanup == "CLEANUP_UNVERIFIED"
            else "CLOSED"
        )
        self._event("TCX_DATA_FINALIZED", data=self.data.snapshot())
        self._event(
            "CLEANUP_VERIFIED"
            if self.cleanup in {"FIXTURE_VERIFIED", "PROCESS_AND_AUDIT_VERIFIED"}
            else "CLEANUP_UNVERIFIED"
        )
        self._event("BROKER_STOPPED")
        return self.snapshot()

    def _terminate_fixture(self) -> None:
        # Ordinary fixture child only; never signal an unverified privileged PID.
        self.child.terminate()
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait(timeout=2)

    def snapshot(self) -> dict:
        return {
            "state": self.state,
            "os_authentication": self.authentication,
            "broker_handoff": (
                "FIXTURE_VERIFIED"
                if self.origin == "B2J_TRANSPORT_FIXTURE_NOT_OS_AUTH"
                else "OS_HANDOFF_VERIFIED"
            )
            if self.deadline and not self.ended
            else self.state,
            "broker_session": str(self.plan.broker.application.application_session),
            "release_integrity": "PACKAGE_VERIFIED_NOT_ROOT_INSTALLATION",
            "release_manifest_digest": self.release.identity,
            "capability_state": "UNKNOWN_NATIVE_PENDING",
            "native_gate": "BLOCKED",
            "cleanup_status": self.cleanup,
            "broker_error": self.broker_error,
            "loader_diagnostics": self.loader_diagnostics,
            "verifier_log": self.verifier_log,
            "fd_release_evidence": self.fd_release_evidence,
            "source": self.origin,
            "collector_state": self.collector_state,
            "tcx_link": self.link_evidence,
            "qualification_only": self.qualification_only,
            "data_plane": self.data.snapshot(),
            "last_error": self.error,
            "native_ai": "BLOCKED",
            "dns9": "BLOCKED",
            "operational_promotion": "BLOCKED",
        }
