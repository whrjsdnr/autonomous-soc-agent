"""Unprivileged PacketCapture-compatible metadata receiver, authenticated via Linux peer state."""

import errno
import hashlib
import os
import queue
import select
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
from soc_agent.security_ai.research.models import Frozen, digest

HELPER_ERRORS = frozenset(
    {
        "HELPER_CAPTURE_COUNTER_UNAVAILABLE",
        "HELPER_CAPTURE_DROPS_DETECTED",
        "HELPER_TRANSPORT_TIMEOUT",
        "HELPER_WATCHDOG_EXPIRED",
        "HELPER_INTERFACE_REPLACED",
        "STREAM_RATE_BUDGET_EXCEEDED",
        "STREAM_MONOTONIC_CLOCK_REVERSED",
    }
)


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


def validate_peer(channel, ready: Message, session: Session, directory: Path, *, module=MODULE):
    if module not in {
        MODULE,
        "soc_agent.security_ai.operational.network_capture.stream_helper",
        "soc_agent.security_ai.operational.network_capture.total_helper",
        "soc_agent.security_ai.operational.network_capture.calibrated_helper",
        "soc_agent.continuous.dns_helper",
    }:
        raise CaptureUnavailable("HELPER_MODULE_NOT_ALLOWLISTED")
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
    expected = [b"-I", b"-m", module.encode(), b"--directory", os.fsencode(directory)]
    if module != MODULE:
        expected.extend([b"--session-digest", digest(session.model_dump(mode="json")).encode()])
    if module == "soc_agent.security_ai.operational.network_capture.calibrated_helper":
        from soc_agent.security_ai.operational.network_capture.calibrated_session import (
            approval_digest,
        )

        expected.extend([b"--approval-digest", approval_digest(session).encode()])
    if arguments[1:-1] != expected:
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
    helper_module = MODULE

    def __init__(self, directory: Path, session: Session, *, queue_capacity=None):
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
        self.reader_thread: threading.Thread | None = None
        self.reader_error: str | None = None
        # At most 512 metadata records (4 MiB encoded upper bound), tied to the
        # already approved frame budget. This is not a second persistent queue.
        capacity = session.max_packets if queue_capacity is None else queue_capacity
        if not 1 <= capacity <= 512:
            self.listener.close()
            raise CaptureUnavailable("HELPER_TRANSPORT_QUEUE_LIMIT")
        self.packets: queue.Queue[PacketObservation] = queue.Queue(maxsize=capacity)
        self.reader_lock = threading.RLock()
        self.queue_high_water = 0
        self.delivered = 0
        self.records_read = 0
        self.last_delivered_at = None
        self.shutdown_reason = None
        self.rejected_closed_digest: str | None = None
        self.reader_last_poll = None
        self.reader_max_poll_gap = 0.0

    def start_reader(self):
        """One bounded metadata reader, independent of SQLite/model/event-loop work."""
        with self.reader_lock:
            if (
                self.reader_thread is not None
                or self.closed.is_set()
                or self.ready is None
                or self.channel is None
            ):
                raise CaptureUnavailable("HELPER_READER_START_INVALID")
            self.reader_thread = threading.Thread(
                target=self._read_loop, name="soc-live-metadata-reader", daemon=True
            )
            try:
                self.reader_thread.start()
            except RuntimeError:
                self.reader_thread = None
                self.reader_error = "HELPER_READER_START_FAILED"
                raise CaptureUnavailable(self.reader_error) from None

    def _read_loop(self):
        try:
            while not self.closed.is_set():
                polled = time.monotonic()
                if self.reader_last_poll is not None:
                    self.reader_max_poll_gap = max(
                        self.reader_max_poll_gap, polled - self.reader_last_poll
                    )
                self.reader_last_poll = polled
                # A descheduled reader may already have authenticated control
                # evidence waiting in the socket. Inspect readiness before declaring
                # silence; an empty socket still has the unchanged two-second bound.
                readable, _, _ = select.select([self.channel], [], [], 0.05)
                if not readable:
                    if time.monotonic() - self.last_heartbeat > 2:
                        raise CaptureUnavailable("HELPER_HEARTBEAT_OR_PROCESS_STALE")
                    continue
                with self.reader_lock:
                    try:
                        message = self.message()
                    except BlockingIOError:
                        continue
                    self.records_read += 1
                    packet = self._receive_record(message)
                    if packet is not None:
                        try:
                            self.packets.put_nowait(packet)
                        except queue.Full:
                            raise CaptureUnavailable("HELPER_TRANSPORT_BACKPRESSURE") from None
                        self.queue_high_water = max(self.queue_high_water, self.packets.qsize())
                    if self.terminal is not None:
                        return
        except (OSError, ValueError, RuntimeError, TypeError) as error:
            if not self.closed.is_set():
                code = (
                    str(error) if isinstance(error, CaptureUnavailable) else "HELPER_READER_FAILED"
                )
                with self.reader_lock:
                    self.reader_error = code
                    self.alive = False
                    try:
                        write_private(
                            self.directory / "transport-failure.json",
                            {
                                "error": code,
                                "stage": "AUTHENTICATED_HELPER_READER",
                                "at_unix": time.time(),
                                "last_heartbeat_age_seconds": time.monotonic()
                                - self.last_heartbeat,
                                "heartbeat_deadline_seconds": 2,
                                "reader_max_poll_gap_seconds": self.reader_max_poll_gap,
                                "helper_pid": self.ready.pid if self.ready is not None else None,
                                "session": str(self.session.session_id),
                                "reader_loop": "HelperCapture._read_loop",
                                "queue_depth": self.packets.qsize(),
                                "queue_capacity": self.packets.maxsize,
                                "queue_high_water": self.queue_high_water,
                                "records_read": self.records_read,
                                "delivered_packets": self.delivered,
                                "last_packet_sequence": self.sequence,
                                "last_counter_sequence": self.counter_sequence,
                                "counter_issue": self.counter_issue,
                                "unadmitted_packets": self.sequence
                                - self.delivered
                                - self.packets.qsize(),
                            },
                        )
                    except (OSError, ValueError):
                        self.reader_error = "HELPER_TRANSPORT_DIAGNOSTIC_WRITE_FAILED"
                    finally:
                        # Disconnect is a bounded helper stop condition. No retry/reconnect.
                        try:
                            self.channel.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

    def reader_failed(self):
        with self.reader_lock:
            if (
                self.reader_thread is not None
                and not self.reader_thread.is_alive()
                and self.terminal is None
                and not self.closed.is_set()
            ):
                self.reader_error = self.reader_error or "HELPER_READER_EXITED_UNEXPECTEDLY"
                self.alive = False
            return self.reader_error is not None

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
                "helper_error": message.error if message.error in HELPER_ERRORS else None,
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
            except OSError as error:
                # close() may race with the blocking accept(). Preserve an
                # explicit owner-stop result, rather than an incidental EBADF.
                # Unrelated accept failures must retain their original errno.
                if self.closed.is_set() and error.errno in (errno.EBADF, errno.EINVAL):
                    raise CaptureUnavailable("HELPER_LISTENER_CLOSED") from error
                raise
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
        if self.helper_module == MODULE:
            validate_peer(channel, ready, self.session, self.directory)
        else:
            validate_peer(channel, ready, self.session, self.directory, module=self.helper_module)
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
        if self.reader_failed():
            raise CaptureUnavailable(self.reader_error)
        if self.ready is None or (not self.alive and self.terminal is None):
            raise CaptureUnavailable("HELPER_VERIFIED_READY_REQUIRED")

    def receive(self):
        if self.closed.is_set():
            return None
        if self.reader_thread is not None:
            with self.reader_lock:
                if self.reader_failed():
                    raise CaptureUnavailable(self.reader_error)
                try:
                    packet = self.packets.get_nowait()
                except queue.Empty:
                    if self.terminal is not None and self.stop:
                        self.stop.set()
                    return None
                self.delivered += 1
                self.last_delivered_at = packet.timestamp
                return packet
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

    def flow_watermark(self, now):
        """Never expire queued/capture-ended traffic using processor wall time."""
        with self.reader_lock:
            if self.reader_thread is not None and self.last_delivered_at is not None:
                return self.last_delivered_at
            return now

    def completion_verified(self):
        with self.reader_lock:
            end = self.terminal
            return bool(
                end is not None
                and not self.reader_failed()
                and self.counter_issue is None
                and end.error is None
                and end.counter_status == "COUNTER_VERIFIED"
                and end.capture_drops_total == 0
                and end.sent_packets == self.sequence == self.delivered
                and end.received_frames is not None
                and self.delivered <= end.received_frames <= self.session.max_packets
                and end.elapsed_seconds is not None
                and end.elapsed_seconds <= self.session.seconds
                and self.packets.empty()
            )

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
        except CaptureUnavailable as error:
            write_private(self.directory / "counter-failure.json", self.counter_issue)
            if message.kind == "CLOSED":
                self._record_rejected_closed(message, str(error))
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
                error = (
                    "HELPER_UNCLEAN_SHUTDOWN"
                    if message.capabilities != self.ready.capabilities
                    else message.error
                    if message.error in HELPER_ERRORS
                    else "HELPER_UNCLEAN_SHUTDOWN"
                )
                self._record_rejected_closed(message, error)
                raise CaptureUnavailable(error)
            write_private(self.directory / "verified-closed.json", message.model_dump(mode="json"))
            # Publish terminal readiness only after the evidence write succeeds.
            self.terminal = message
            self.alive = False
            if self.stop and self.reader_thread is None:
                self.stop.set()
        return None

    def _record_rejected_closed(self, message: Message, reason: str) -> None:
        """Bounded diagnostics after peer/schema checks; never a completion receipt."""
        fields = (
            "session_id",
            "counter_sequence",
            "counter_status",
            "counter_detail",
            "kernel_packets",
            "capture_drops",
            "kernel_packets_total",
            "capture_drops_total",
            "received_frames",
            "sent_packets",
            "elapsed_seconds",
            "rss_peak_bytes",
            "cpu_seconds",
        )
        value = message.model_dump(mode="json", include=set(fields))
        value.update(
            contract="soc-rejected-helper-closed:v1",
            completion_verified=False,
            rejection_reason=reason,
            helper_error=message.error if message.error in HELPER_ERRORS else None,
            counter_validation="ACCEPTED" if self.counter_issue is None else "REJECTED",
            capabilities_match=self.ready is not None
            and message.capabilities == self.ready.capabilities,
        )
        write_private(self.directory / "rejected-closed.json", value)
        self.rejected_closed_digest = digest(value)

    def statistics(self):
        with self.reader_lock:
            if self.reader_failed():
                raise CaptureUnavailable(self.reader_error)
            return self._statistics()

    def _statistics(self):
        if self.counter_issue:
            raise CaptureUnavailable(self.counter_issue["error"])
        if self.closed.is_set() and self.terminal is None:
            raise CaptureUnavailable("HELPER_FINAL_COUNTERS_MISSING")
        if self.last_heartbeat is None or (
            self.alive and time.monotonic() - self.last_heartbeat > 2
        ):
            raise CaptureUnavailable("HELPER_HEARTBEAT_OR_PROCESS_STALE")
        values, self.deltas = tuple(self.deltas), [0, 0]
        return values

    def is_live(self):
        try:
            return bool(
                not self.reader_failed()
                and self.alive
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
        with self.reader_lock:
            return {
                **self.usage,
                "counter_sequence": self.counter_sequence,
                "capture_counter_issue": self.counter_issue,
                "transport_reader_running": bool(
                    self.reader_thread and self.reader_thread.is_alive()
                ),
                "transport_error": self.reader_error,
                "transport_queue_depth": self.packets.qsize(),
                "transport_queue_capacity": self.packets.maxsize,
                "transport_queue_high_water": self.queue_high_water,
                "transport_delivered_packets": self.delivered,
                "transport_final_counter_verified": self.terminal is not None,
                "rejected_closed_digest": self.rejected_closed_digest,
            }

    def close(self, *, reason="EXPLICIT_STOP_BEFORE_PERSISTENCE"):
        with self.transport_lock:
            self.shutdown_reason = self.shutdown_reason or reason
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
        if self.reader_thread is not None:
            self.reader_thread.join(2)
            if self.reader_thread.is_alive():
                raise CaptureUnavailable("HELPER_READER_SHUTDOWN_UNCERTAIN")
        with self.transport_lock:
            if self.packets.empty():
                return
            # Unpersisted metadata is explicitly accounted for, never called delivered.
            path = self.directory / "transport-unprocessed.json"
            if not path.exists():
                write_private(
                    path,
                    {
                        "queued_packets": self.packets.qsize(),
                        "delivered_packets": self.delivered,
                        "reason": self.reader_error or self.shutdown_reason,
                    },
                )
