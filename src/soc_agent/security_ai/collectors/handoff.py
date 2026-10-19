"""Same-UID bounded Unix control handshake; no capture, passwords or privilege calls."""

import asyncio
import json
import os
import socket
import sqlite3
import struct
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import Frozen

StopReason = Literal[
    "USER_STOP",
    "GUI_CLOSE",
    "CONTROLLER_EXIT",
    "PREPARATION_CANCELLED",
    "LAUNCH_FAILED",
    "COLLECTOR_EXIT",
    "TIMEOUT",
]

ERRORS = frozenset(
    {
        "ZEEK_PRIOR_CONTAINER_REVIEW_REQUIRED",
        "ZEEK_SCOPE_APPROVAL_CANCELLED",
        "ZEEK_AUTH_INTERRUPTED",
        "ZEEK_STARTUP_INTERRUPTED",
        "ZEEK_STARTUP_PHASE_INVALID",
        "ZEEK_SHUTDOWN_UNVERIFIED",
        "ZEEK_COLLECTOR_NOT_STARTED",
        "ZEEK_GUI_START_FAILED",
        "ZEEK_RESOURCE_PRESSURE_REQUIRED",
        "ZEEK_SESSION_RETENTION_REVIEW_REQUIRED",
        "ZEEK_CONTROLLER_NOT_RUNNING",
        "ZEEK_CLOSED_ACCOUNTING_MISMATCH",
        "ZEEK_CONTAINER_CLEANUP_UNVERIFIED",
        "ZEEK_NATIVE_UNREQUESTED_EXIT",
        "ZEEK_STREAM_READY_INVALID",
        "ZEEK_STREAM_PACKET_INTEGRITY",
        "ZEEK_STREAM_PRIVACY_REJECTED",
        "ZEEK_CONTROLLER_IDENTITY_MISMATCH",
        "ZEEK_SESSION_STOP_REQUESTED",
        "ZEEK_SESSION_REUSE_DENIED",
        "ZEEK_APPROVAL_DIGEST_MISMATCH",
        "ZEEK_DOCKER_START_FAILED",
        "ZEEK_CONTAINER_EXIT_UNVERIFIED",
        "ZEEK_LISTENER_UNAVAILABLE",
        "ZEEK_PROCESS_DEADLINE_EXCEEDED",
        "ZEEK_AUTH_DENIED_CANCELLED_OR_TIMEOUT",
        "ZEEK_LIVE_BUNDLE_CHANGED",
        "ZEEK_NETWORK_NAMESPACE_CHANGED",
        "ZEEK_LIVE_PREPARATION_FAILED",
        "ZEEK_AUDIT_PERSISTENCE_FAILED",
        "ZEEK_STOP_SIGNAL_PERSISTENCE_FAILED",
        "ZEEK_LAUNCHER_EXIT_WITHOUT_CLOSED",
        "ZEEK_CLOSED_OR_PROCESS_INTEGRITY_UNVERIFIED",
        "ZEEK_PROCESS_EXIT_UNRECORDED",
        "ZEEK_LIVE_INTEGRITY_FAILED",
        "ZEEK_PROCESS_STOP_UNVERIFIED",
        "ZEEK_STOP_DEADLINE_UNVERIFIED",
        "ZEEK_STREAM_OUTPUT_BUDGET",
        "ZEEK_STREAM_SEQUENCE_INTEGRITY",
        "ZEEK_STREAM_RECORD_BOUND",
        "ZEEK_PARTIAL_RECORD_ON_CLOSE",
        "ZEEK_CONTAINER_STOP_UNVERIFIED",
        "ZEEK_CAPTURE_DROPS_DETECTED",
        "ZEEK_FLOW_TIMESTAMP_REGRESSION",
        "ZEEK_LOG_TRUNCATED",
        "ZEEK_AUTH_FAILURE_IDENTITY_INVALID",
    }
)


def safe_code(error: object) -> str:
    code = str(error)
    return code if code in ERRORS else "ZEEK_LIVE_INTEGRITY_FAILED"


def process_identity(pid: int) -> dict:
    stat = Path(f"/proc/{pid}/stat").read_text()
    if stat.rsplit(")", 1)[1].split()[0] in {"Z", "X"}:
        raise ProcessLookupError("process has exited")
    return dict(pid=pid, start_ticks=stat.rsplit(")", 1)[1].split()[19])


def same_process(identity: dict) -> bool:
    try:
        return process_identity(identity["pid"]) == identity
    except (OSError, ValueError, KeyError, TypeError):
        return False


class Controller(Frozen):
    pid: int = Field(gt=0, strict=True)
    start_ticks: str = Field(pattern=r"^[0-9]+$")
    session_id: UUID
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    generation: UUID
    address: str = Field(pattern=r"^@soc-zeek-[a-f0-9]{32}-[a-f0-9]{32}$")


def controller_identity(plan) -> Controller:
    return Controller(
        **process_identity(os.getpid()),
        session_id=plan.session_id,
        plan_digest=plan.identity,
        generation=plan.controller_generation,
        address="@soc-zeek-" + plan.session_id.hex + "-" + plan.controller_generation.hex,
    )


def read_controller(directory: Path, plan) -> Controller:
    try:
        c = Controller.model_validate_json(read_local(directory / "controller.json", 8192))
    except (OSError, ValueError) as error:
        raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH") from error
    if (
        c.session_id != plan.session_id
        or c.plan_digest != plan.identity
        or c.generation != plan.controller_generation
        or c.address != "@soc-zeek-" + plan.session_id.hex + "-" + plan.controller_generation.hex
    ):
        raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
    identity = dict(pid=c.pid, start_ticks=c.start_ticks)
    try:
        current = process_identity(c.pid)
    except OSError as error:
        raise ValueError("ZEEK_CONTROLLER_NOT_RUNNING") from error
    if current != identity:
        raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
    if (directory / "stop.request").exists():
        raise ValueError("ZEEK_SESSION_STOP_REQUESTED")
    return c


def exchange(directory: Path, plan, operation: str) -> dict:
    """Blocking launcher call; execute off the GUI event loop. Kernel peer PID is checked."""
    c = read_controller(directory, plan)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(2)
            channel.connect("\0" + c.address[1:])
            pid, uid, _ = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if pid != c.pid or uid != os.getuid():
                raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
            request = dict(
                operation=operation,
                controller=c.model_dump(mode="json"),
                launcher=process_identity(os.getpid()),
            )
            channel.sendall(json.dumps(request).encode() + b"\n")
            with channel.makefile("rb") as stream:
                raw = stream.readline(4097)
            if len(raw) > 4096 or not raw.endswith(b"\n"):
                raise ValueError("ZEEK_LISTENER_UNAVAILABLE")
            result = json.loads(raw)
            if result.get("controller") != c.model_dump(mode="json"):
                raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
            if result.get("status") != "OK":
                raise ValueError(safe_code(result.get("error")))
            return result
    except (OSError, TimeoutError, json.JSONDecodeError) as error:
        raise ValueError("ZEEK_LISTENER_UNAVAILABLE") from error


class Handoff:
    def __init__(self, plan, event, authorize):
        self.identity = controller_identity(plan)
        self.event = event
        self.authorize = authorize
        self.server = None
        self.accepted = None
        self.claimed_at = None
        self.connections = set()
        self.limit = asyncio.Semaphore(4)
        self.stopped = False
        self.failure = None

    @property
    def ready(self):
        return bool(self.server and self.server.is_serving() and not self.stopped)

    @property
    def command_valid(self):
        return self.ready and self.accepted is None

    async def start(self):
        self.server = await asyncio.start_unix_server(
            self._handle, path="\0" + self.identity.address[1:], limit=4097, backlog=4
        )
        if not self.ready:
            raise ValueError("ZEEK_LISTENER_UNAVAILABLE")

    def _record(self, kind, details):
        try:
            self.event(kind, details)
            return True
        except (OSError, ValueError, sqlite3.Error):
            self.failure = "ZEEK_AUDIT_PERSISTENCE_FAILED"
            self.stopped = True
            if self.server:
                self.server.close()
            return False

    async def _handle(self, reader, writer):
        # Bound idle clients as well as messages; never queue unlimited handlers.
        if len(self.connections) >= 4:
            writer.close()
            await writer.wait_closed()
            return
        self.connections.add(writer)
        result = dict(status="ERROR", controller=self.identity.model_dump(mode="json"))
        try:
            async with self.limit:
                raw = await asyncio.wait_for(reader.readline(), 2)
                if len(raw) > 4096 or not raw.endswith(b"\n") or not self.ready:
                    raise ValueError("ZEEK_LISTENER_UNAVAILABLE")
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
                pid, uid, _ = struct.unpack(
                    "3i",
                    writer.get_extra_info("socket").getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                    ),
                )
                if uid != os.getuid() or value.get("controller") != self.identity.model_dump(
                    mode="json"
                ):
                    raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
                peer = value.get("launcher")
                if not isinstance(peer, dict) or peer.get("pid") != pid or not same_process(peer):
                    raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
                self.authorize()
                operation = value.get("operation")
                if operation == "claim":
                    if not self.command_valid:
                        raise ValueError("ZEEK_SESSION_REUSE_DENIED")
                    if not self._record("LAUNCHER_ACCEPTED", dict(launcher=peer)):
                        raise ValueError("ZEEK_AUDIT_PERSISTENCE_FAILED")
                    self.accepted = peer
                    self.claimed_at = asyncio.get_running_loop().time()
                elif operation == "validate":
                    if self.accepted != peer:
                        raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
                elif operation != "probe":
                    raise ValueError("ZEEK_CONTROLLER_IDENTITY_MISMATCH")
                result["status"] = "OK"
        except (OSError, ValueError, TimeoutError, KeyError, TypeError) as error:
            result["error"] = safe_code(error)
            self._record("LAUNCHER_REJECTED", dict(error=result["error"]))
        try:
            writer.write(json.dumps(result).encode() + b"\n")
            await writer.drain()
        except (OSError, ConnectionError):
            # The claim stays consumed when a client disappears before reading ACK.
            self._record("LAUNCHER_REJECTED", dict(error="ZEEK_LISTENER_UNAVAILABLE"))
        finally:
            self.connections.discard(writer)
            writer.close()
            await writer.wait_closed()

    async def close(self):
        self.stopped = True
        if self.server:
            self.server.close()
        for writer in tuple(self.connections):
            writer.close()
        if self.server:
            await asyncio.wait_for(self.server.wait_closed(), 3)
