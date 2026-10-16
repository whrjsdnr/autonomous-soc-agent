"""Unprivileged PacketCapture-compatible metadata receiver, authenticated via Linux peer state."""

import hashlib
import os
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.live_helper import process_start
from soc_agent.security_ai.operational.network_capture.live_session import (
    MODULE,
    Session,
    write_private,
)
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.operational.network_capture.permissions import NET_RAW
from soc_agent.security_ai.research.models import Frozen


class Message(Frozen):
    kind: Literal["READY", "PACKET", "HEARTBEAT", "CLOSED"]
    session_id: UUID
    pid: int | None = Field(default=None, gt=1)
    process_start: str | None = None
    socket_fd: int | None = Field(default=None, ge=3)
    socket_inode: int | None = Field(default=None, gt=0)
    capabilities: dict[str, int | None] | None = None
    sequence: int | None = Field(default=None, ge=1, le=512)
    packet: PacketObservation | None = None
    kernel_packets: int | None = Field(default=None, ge=0, lt=2**32, strict=True)
    capture_drops: int | None = Field(default=None, ge=0, lt=2**32, strict=True)
    counter_sequence: int | None = Field(default=None, ge=1, le=2048, strict=True)
    counter_status: (
        Literal["COUNTER_VERIFIED", "COUNTER_UNAVAILABLE", "CAPTURE_DROPS_DETECTED"] | None
    ) = None
    counter_detail: str | None = Field(default=None, pattern=r"^[A-Z0-9_]{1,64}$")
    kernel_packets_total: int | None = Field(default=None, ge=0, strict=True)
    capture_drops_total: int | None = Field(default=None, ge=0, strict=True)
    received_frames: int | None = Field(default=None, ge=0, le=512)
    sent_packets: int | None = Field(default=None, ge=0, le=512)
    elapsed_seconds: float | None = Field(default=None, ge=0, le=62)
    error: str | None = Field(default=None, max_length=64)
    rss_peak_bytes: int | None = Field(default=None, ge=0)
    cpu_seconds: float | None = Field(default=None, ge=0)


def validate_peer(channel, ready: Message, session: Session, directory: Path):
    pid, uid, gid = struct.unpack(
        "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    expected_caps = dict(
        euid=session.uid,
        egid=session.gid,
        CapEff=0,
        CapPrm=0,
        CapInh=0,
        CapAmb=0,
        CapBnd=NET_RAW,
        NoNewPrivs=1,
    )
    if (
        ready.kind != "READY"
        or (pid, uid, gid) != (ready.pid, session.uid, session.gid)
        or ready.session_id != session.session_id
        or ready.capabilities != expected_caps
        or process_start(pid) != ready.process_start
    ):
        raise CaptureUnavailable("HELPER_READY_PEER_MISMATCH")
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if arguments[1:-1] != [b"-I", b"-m", MODULE.encode(), b"--directory", os.fsencode(directory)]:
        raise CaptureUnavailable("HELPER_COMMAND_MISMATCH")
    if hashlib.sha256(Path(f"/proc/{pid}/exe").read_bytes()).hexdigest() != session.python_sha256:
        raise CaptureUnavailable("HELPER_INTERPRETER_MISMATCH")
    fields = dict(
        line.split(":", 1)
        for line in Path(f"/proc/{pid}/status").read_text().splitlines()
        if ":" in line
    )
    for key, value in (("Uid", session.uid), ("Gid", session.gid)):
        if tuple(map(int, fields[key].split())) != (value,) * 4:
            raise CaptureUnavailable("HELPER_OS_IDENTITY_MISMATCH")
    if (
        fields["Groups"].strip()
        or any(
            int(fields[k], 16) != expected_caps[k]
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
        )
        or int(fields["NoNewPrivs"]) != 1
    ):
        raise CaptureUnavailable("HELPER_CAPABILITIES_NOT_DROPPED")
    if os.readlink(f"/proc/{pid}/fd/{ready.socket_fd}") != f"socket:[{ready.socket_inode}]":
        raise CaptureUnavailable("HELPER_CAPTURE_SOCKET_MISMATCH")
    rows = [
        line.split()
        for line in Path("/proc/net/packet").read_text().splitlines()[1:]
        if line.split()[-1] == str(ready.socket_inode)
    ]
    if (
        len(rows) != 1
        or (int(rows[0][2]), int(rows[0][3], 16), int(rows[0][4]), int(rows[0][7]))
        != (socket.SOCK_RAW, 3, socket.if_nametoindex("lo"), session.uid)
        or interface_identity("lo") != session.interface_id
    ):
        raise CaptureUnavailable("HELPER_INTERFACE_SOCKET_BINDING_MISMATCH")


class HelperCapture:
    control_batch = 64

    def __init__(self, directory: Path, session: Session):
        self.directory, self.session = directory, session
        self.identity = session.interface_id
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self.listener.bind(session.socket_address)
            self.listener.listen(1)
            self.listener.settimeout(0.2)
        except OSError:
            self.listener.close()
            raise
        self.channel = None
        self.ready = None
        self.closed = threading.Event()
        self.transport_lock = threading.Lock()
        self.alive = False
        self.stop = None
        self.sequence = 0
        self.deltas = [0, 0]
        self.last_heartbeat = None
        self.terminal = None
        self.usage = {}
        self.counter_sequence = 0
        self.counter_totals = [0, 0]
        self.counter_issue = None

    def accept_counters(self, message):
        """Validate each kernel reset interval exactly once before exposing deltas."""
        if self.counter_issue:
            raise CaptureUnavailable(self.counter_issue["error"])
        error, detail = None, message.counter_detail
        if message.counter_sequence != self.counter_sequence + 1:
            error, detail = "HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED", "COUNTER_SEQUENCE_MISMATCH"
        elif (
            message.counter_status == "COUNTER_UNAVAILABLE"
            or message.kernel_packets is None
            or message.capture_drops is None
            or message.kernel_packets_total is None
            or message.capture_drops_total is None
        ):
            error = "HELPER_CAPTURE_COUNTER_UNAVAILABLE"
        elif (
            message.capture_drops > message.kernel_packets
            or message.kernel_packets_total != self.counter_totals[0] + message.kernel_packets
            or message.capture_drops_total != self.counter_totals[1] + message.capture_drops
            or message.counter_status
            != ("CAPTURE_DROPS_DETECTED" if message.capture_drops_total else "COUNTER_VERIFIED")
            or message.counter_detail is not None
        ):
            error, detail = (
                "HELPER_CAPTURE_COUNTER_INTEGRITY_FAILED",
                "COUNTER_TOTAL_OR_STATUS_MISMATCH",
            )
        elif message.capture_drops_total:
            error = "HELPER_CAPTURE_DROPS_DETECTED"
        if error:
            self.counter_issue = {
                "error": error,
                "counter_detail": detail,
                "counter_sequence": message.counter_sequence,
                "kernel_packets": message.kernel_packets,
                "capture_drops": message.capture_drops,
                "kernel_packets_total": message.kernel_packets_total,
                "capture_drops_total": message.capture_drops_total,
                "helper_error": message.error
                if message.error
                in {
                    "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
                    "HELPER_CAPTURE_DROPS_DETECTED",
                    "HELPER_TRANSPORT_TIMEOUT",
                    "HELPER_WATCHDOG_EXPIRED",
                }
                else None,
            }
            self.alive = False
            raise CaptureUnavailable(error)
        self.counter_sequence = message.counter_sequence
        self.counter_totals = [message.kernel_packets_total, message.capture_drops_total]
        self.deltas[0] += message.kernel_packets
        self.deltas[1] += message.capture_drops

    def listener_ready(self):
        """Observer readiness, distinct from the privileged helper's verified READY."""
        try:
            return bool(
                not self.closed.is_set()
                and self.channel is None
                and self.listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            )
        except OSError:
            return False

    def handshake(self):
        # Operator authentication has no hidden expiry. Only explicit Stop/GUI close
        # ends this wait; the helper's capture watchdog remains independently bounded.
        while not self.closed.is_set():
            try:
                channel, _ = self.listener.accept()
                break
            except TimeoutError:
                continue
        else:
            raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
        with self.transport_lock:
            if self.closed.is_set():
                channel.close()
                raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
            self.channel = channel
            # Exactly one authenticated helper per session; no queued reconnects.
            self.listener.close()
        channel.settimeout(2)
        ready = self.message()
        validate_peer(channel, ready, self.session, self.directory)
        try:
            self.accept_counters(ready)
        except CaptureUnavailable:
            write_private(self.directory / "counter-failure.json", self.counter_issue)
            raise
        with self.transport_lock:
            if self.closed.is_set():
                raise CaptureUnavailable("HELPER_LISTENER_CLOSED")
            write_private(self.directory / "verified-ready.json", ready.model_dump(mode="json"))
            self.ready = ready
            self.alive = True
            self.last_heartbeat = time.monotonic()
        self.usage = {
            "helper_rss_peak_bytes": ready.rss_peak_bytes,
            "helper_cpu_seconds": ready.cpu_seconds,
            "received_frames": ready.received_frames,
            "metadata_packets": ready.sent_packets,
        }
        channel.setblocking(False)

    def message(self):
        body, _, flags, _ = self.channel.recvmsg(8192)
        if flags & socket.MSG_TRUNC or not body:
            raise CaptureUnavailable("HELPER_DISCONNECTED_OR_RECORD_LIMIT")
        value = Message.model_validate_json(body)
        if value.session_id != self.session.session_id:
            raise CaptureUnavailable("HELPER_SESSION_FORGERY")
        return value

    def open(self):
        if not self.alive or self.ready is None:
            raise CaptureUnavailable("HELPER_VERIFIED_READY_REQUIRED")

    def receive(self):
        if not self.alive:
            return None
        # Control records are not an empty input queue. Drain a bounded number
        # before yielding, so each heartbeat does not force the monitor's idle sleep.
        for _ in range(self.control_batch):
            try:
                message = self.message()
            except BlockingIOError:
                return None
            packet = self._receive_record(message)
            if packet is not None or not self.alive:
                return packet
        return None

    def _receive_record(self, message):
        if message.kind == "PACKET":
            p = message.packet
            if (
                message.sequence != self.sequence + 1
                or p is None
                or p.interface_id != self.identity
                or p.timestamp_origin != "KERNEL_SO_TIMESTAMPNS"
                or p.direction != "OUTBOUND"
                or p.dns is not None
            ):
                raise CaptureUnavailable("HELPER_PACKET_BINDING_MISMATCH")
            self.sequence += 1
            return p
        if message.kind not in {"HEARTBEAT", "CLOSED"}:
            raise CaptureUnavailable("HELPER_PROTOCOL_FAILURE")
        # Persist authenticated diagnostics before rejection, not a success receipt.
        try:
            self.accept_counters(message)
        except CaptureUnavailable:
            write_private(self.directory / "counter-failure.json", self.counter_issue)
            raise
        self.last_heartbeat = time.monotonic()
        self.usage = {
            "helper_rss_peak_bytes": message.rss_peak_bytes,
            "helper_cpu_seconds": message.cpu_seconds,
            "received_frames": message.received_frames,
            "metadata_packets": message.sent_packets,
        }
        if message.kind == "CLOSED":
            if message.error or message.capabilities != self.ready.capabilities:
                raise CaptureUnavailable("HELPER_UNCLEAN_SHUTDOWN")
            self.terminal = message
            write_private(self.directory / "verified-closed.json", message.model_dump(mode="json"))
            self.alive = False
            if self.stop:
                self.stop.set()
        return None

    def statistics(self):
        if self.counter_issue:
            raise CaptureUnavailable(self.counter_issue["error"])
        if self.last_heartbeat is None or (
            self.alive and time.monotonic() - self.last_heartbeat > 2
        ):
            raise CaptureUnavailable("HELPER_HEARTBEAT_OR_PROCESS_STALE")
        values, self.deltas = tuple(self.deltas), [0, 0]
        return values

    def is_live(self):
        try:
            return bool(
                self.alive
                and self.ready
                and self.last_heartbeat
                and time.monotonic() - self.last_heartbeat <= 2
                and process_start(self.ready.pid) == self.ready.process_start
                and Path(f"/proc/{self.ready.pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                not in {"Z", "X"}
            )
        except (OSError, ValueError):
            return False

    def extra_metrics(self):
        return {
            **self.usage,
            "counter_sequence": self.counter_sequence,
            "capture_counter_issue": self.counter_issue,
        }

    def close(self):
        with self.transport_lock:
            self.alive = False
            self.closed.set()
            if self.channel is not None:
                try:
                    self.channel.send(b"STOP", socket.MSG_DONTWAIT)
                    self.channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Disconnect is itself a stop condition for the bounded helper.
                self.channel.close()
            self.listener.close()
