"""Independent bounded metadata transport; never executes a loader or model."""

import array
import os
import select
import socket
import struct
import threading
import time
from functools import wraps
from pathlib import Path

from soc_agent.security_ai.ebpf.clock import ClockContract
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.models import Plan
from soc_agent.security_ai.ebpf_native.contracts import process_identity
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan

HEADER = struct.Struct("<4IQQ16s32s32s")
CREDENTIAL = struct.Struct("3i")
MAGIC = 0x31445053
ROW_BYTES = HEADER.size + 80


def synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)

    return call


class PacketChannel:
    def __init__(self, plan: NativePlan, approval: str, directory: Path):
        self.plan, self.approval, self.directory = plan, approval, directory
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.listener: socket.socket | None = None
        self.channel: socket.socket | None = None
        self.identity = None
        self.source = 0
        self.sequence = self.loss = self.frames = 0
        self.closed = False
        self.error: str | None = None
        self.adapter: EBPFCollector | None = None
        self.runs = 0
        self.generations: set[int] = set()
        self.queue_overflows = 0
        self.backpressure_events = 0
        self.counter_evidence = None
        self.transport_failed = False

    def listen(self) -> None:
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.listener.settimeout(5)
        app = self.plan.broker.application.application_session.hex
        self.listener.bind(f"\0soc-ebpf-data.{self.plan.broker.uid}.{app}")
        self.listener.listen(1)

    def bind(self, identity, *, fixture: bool) -> None:
        if self.listener is None:
            raise ValueError("TCX_DATA_LISTENER_REQUIRED")
        self.identity, self.source = identity, 2 if fixture else 1
        self.channel, _ = self.listener.accept()
        self.channel.settimeout(5)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        peer = CREDENTIAL.unpack(self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != (identity.pid, self.plan.broker.uid, self.plan.broker.gid):
            raise ValueError("TCX_DATA_PEER_IDENTITY")
        current = process_identity(identity.pid)
        if current.start_ticks != identity.start_ticks or current.uid != self.plan.broker.uid:
            raise ValueError("TCX_DATA_PEER_IDENTITY")
        self.identity = current
        self._receive(ready=True)
        self.worker = threading.Thread(
            target=self._consume, name="tcx-metadata-reader", daemon=True
        )
        self.worker.start()

    def _consume(self) -> None:
        while not self.stop_event.is_set() and not self.closed and not self.transport_failed:
            try:
                if self.channel and select.select([self.channel], [], [], 0.05)[0]:
                    self.pump()
            except (OSError, ValueError) as exc:
                if isinstance(exc, OSError):
                    self.transport_failed = True
                self.error = self.error or "TCX_DATA_READER_FAILURE"
                if not self.transport_failed:
                    # Processing failed, but authenticated terminal/counter frames
                    # still need a reader while Broker performs bounded cleanup.
                    continue
                # pump records the reviewed failure. Broken delivery must stop the
                # producer, not grow buffers or keep a privileged observer running.
                if self.channel:
                    try:
                        self.channel.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        self.error = self.error or "TCX_DATA_SHUTDOWN_UNVERIFIED"
                return

    @synchronized
    def prepare_adapter(self, generation: int, clock: ClockContract | None = None) -> None:
        if not self.source or self.closed or self.error or self.runs >= 16:
            raise ValueError("TCX_DATA_RUN_DENIED")
        if self.adapter and not self.adapter.flow.closed:
            raise ValueError("TCX_DATA_PREVIOUS_RUN_UNFINISHED")
        if generation in self.generations:
            raise ValueError("TCX_DATA_GENERATION_REPLAY")
        scope = self.plan.broker.application.scope
        plan = Plan(
            collector="EBPF_TCX",
            session_id=self.plan.broker.application.application_session,
            generation=generation,
            program_sha256=self.plan.program_sha256,
            source_digest=self.approval,
            ifindex=scope.ifindex,
            net_namespace=scope.net_namespace,
            hook=scope.hook,
            origin="TCX_STREAM_FIXTURE" if self.source == 2 else "EBPF_TC_NATIVE",
            clock="KERNEL_MONOTONIC_NS",
        )
        self.counter_evidence = None
        self.runs += 1
        self.generations.add(generation)
        self.adapter = EBPFCollector(self.directory / f"data-run-{self.runs}", plan)
        self.adapter.prepare_metadata()
        self.adapter.begin_metadata_stream(
            time.monotonic(),
            clock or ClockContract(session_id=plan.session_id, domain=plan.clock),
        )

    def _receive(self, *, ready: bool = False) -> None:
        if self.channel is None or self.identity is None or self.closed:
            raise ValueError("TCX_DATA_CHANNEL_NOT_READY")
        body, ancillary, flags, _ = self.channel.recvmsg(
            ROW_BYTES + 1, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC
        )
        credential = None
        bad = False
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors = array.array("i")
                descriptors.frombytes(value[: len(value) - len(value) % descriptors.itemsize])
                for fd in descriptors:
                    os.close(fd)
                bad = True
            elif (
                level == socket.SOL_SOCKET
                and kind == socket.SCM_CREDENTIALS
                and len(value) == 12
                and credential is None
            ):
                credential = CREDENTIAL.unpack(value)
            else:
                bad = True
        expected = (self.identity.pid, self.plan.broker.uid, self.plan.broker.gid)
        if not body:
            raise ValueError("TCX_DATA_EOF_WITHOUT_CLOSED")
        try:
            current = process_identity(self.identity.pid)
        except FileNotFoundError:
            # Drain already queued, kernel-credentialled records on this bound
            # connection. No new handshake/authentication is accepted after exit.
            current = self.identity
        if (
            bad
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or credential != expected
            or current.start_ticks != self.identity.start_ticks
            or current.uid != expected[1]
        ):
            raise ValueError("TCX_DATA_CREDENTIALS_OR_PID_REUSE")
        if len(body) != ROW_BYTES:
            raise ValueError("TCX_DATA_EOF_OR_SIZE")
        magic, version, kind, source, sequence, loss, app, approval, program = HEADER.unpack_from(
            body
        )
        if (magic, version, source, app, approval.hex(), program.hex()) != (
            MAGIC,
            1,
            self.source,
            self.plan.broker.application.application_session.bytes,
            self.approval,
            self.plan.program_sha256,
        ):
            raise ValueError("TCX_DATA_SOURCE_IDENTITY")
        if loss < self.loss:
            raise ValueError("TCX_DATA_COUNTER_RESET")
        self.loss = loss
        if loss:
            raise ValueError("TCX_DATA_SOCKET_DELIVERY_LOSS")
        if sequence != (0 if ready else self.sequence + 1) or sequence > 65568:
            raise ValueError("TCX_DATA_SEQUENCE_OR_COUNTER_RESET")
        if kind not in ({1} if ready else {2, 3, 4, 5}):
            raise ValueError("TCX_DATA_KIND")
        self.sequence, self.loss = sequence, loss
        self.frames += 1
        if loss:
            raise ValueError("TCX_DATA_SOCKET_DELIVERY_LOSS")
        raw = body[HEADER.size :]
        if kind == 2:
            if self.adapter is None:
                raise ValueError("TCX_DATA_ADAPTER_NOT_PREPARED")
            if self.error and self.adapter.flow.closed:
                self.adapter.discard_after_error(raw)
            else:
                self.adapter.ingest(raw, monotonic=time.monotonic())
                self.adapter.drain()
            self.backpressure_events += int(len(self.adapter.queue) == 24)
        elif kind == 5:
            generation, timestamp, *values = struct.unpack("<QQ7QII", raw)
            totals, status, delivered = values[:7], values[7], values[8]
            if (
                self.adapter is None
                or generation != self.adapter.plan.generation
                or status not in {1, 2}
                or timestamp <= 0
                or delivered > 4096
                or self.counter_evidence is not None
                or status == 2
                and any(totals)
            ):
                raise ValueError("TCX_COUNTER_EVIDENCE_SCHEMA")
            names = (
                "observed",
                "emitted",
                "ring_reservation_failures",
                "unsupported",
                "malformed",
                "disabled",
                "budget",
            )
            self.counter_evidence = dict(
                generation=generation,
                monotonic_ns=timestamp,
                retrieval="SUCCESS" if status == 1 else "UNVERIFIED",
                source=(
                    "TCX_OWNED_MAP_HOOK_PER_CPU_CUMULATIVE_NOT_ZEEK_PCAP_OR_KERNEL_DROPS"
                    if self.source == 1
                    else "FIXTURE_COUNTER_NEVER_NATIVE"
                ),
                delivered=delivered,
                totals=dict(zip(names, totals, strict=True)) if status == 1 else None,
            )
        elif kind == 4:
            generation, reason = struct.unpack_from("<QI", raw[:8] + raw[32:36])
            if raw != struct.pack("<Q", generation) + bytes(24) + struct.pack("<I", reason) + bytes(
                44
            ) or reason not in {1, 2}:
                raise ValueError("TCX_DATA_END_SCHEMA")
            if self.adapter:
                if (
                    generation != self.adapter.plan.generation
                    or self.adapter.flow.closed
                    and not self.error
                ):
                    raise ValueError("TCX_DATA_RUN_IDENTITY")
                if not self.adapter.flow.closed:
                    self.adapter.end_metadata_stream(
                        "PACKET_LIMIT" if reason == 2 else "CAPTURE_STOP"
                    )
        elif any(raw):
            raise ValueError("TCX_DATA_CONTROL_SCHEMA")
        if kind == 3:
            if self.adapter and not self.adapter.flow.closed:
                self.adapter.end_metadata_stream("CAPTURE_STOP")
            self.closed = True

    @synchronized
    def pump(self, limit: int = 32) -> int:
        if not 1 <= limit <= 32:
            raise ValueError("TCX_DATA_PUMP_BOUND")
        count = 0
        try:
            while (
                self.channel
                and not self.closed
                and count < limit
                and select.select([self.channel], [], [], 0)[0]
            ):
                self._receive()
                count += 1
            if self.adapter and self.adapter.queue:
                self.adapter.drain()
        except (ValueError, OSError) as exc:
            code = str(exc) if isinstance(exc, ValueError) else "TCX_DATA_IO_FAILURE"
            self.error = self.error or code
            recoverable = {
                "EBPF_CLOCK_INVALID",
                "EBPF_REORDER_LATE_CAPTURE_GAP",
                "EBPF_QUEUE_OVERFLOW_CAPTURE_GAP",
            }
            self.transport_failed = code not in recoverable
            self.queue_overflows += int(self.error == "EBPF_QUEUE_OVERFLOW_CAPTURE_GAP")
            if self.adapter:
                self.adapter.last_error = self.error
                self.adapter.state = "ERROR"
                self.adapter.end_metadata_stream(
                    "QUEUE_OVERFLOW"
                    if self.queue_overflows
                    else "CLOCK_INVALID"
                    if "CLOCK" in self.error
                    else "INCOMPLETE"
                )
            raise
        return count

    def close(self) -> None:
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=2)
            if self.worker.is_alive():
                self.error = "TCX_DATA_WORKER_SHUTDOWN_UNVERIFIED"
        try:
            if self.channel and not self.transport_failed:
                # Bounded final drain, not an unbounded EOF wait or auto-restart.
                for _ in range(2050):
                    if self.closed or not self.pump():
                        break
            if self.adapter and not self.adapter.flow.closed:
                self.adapter.end_metadata_stream("INCOMPLETE")
            if self.adapter:
                self.adapter.checkpoint()
        finally:
            if self.channel:
                self.channel.close()
                self.channel = None
            if self.listener:
                self.listener.close()
                self.listener = None

    @synchronized
    def snapshot(self) -> dict:
        return dict(
            contract="TCX_SEQPACKET_DATA_V1_192",
            source="ORDINARY_UID_PACKET_FIXTURE"
            if self.source == 2
            else "KERNEL_TCX_NATIVE"
            if self.source == 1
            else "NATIVE_PENDING",
            state="ERROR"
            if self.error
            else "CLOSED"
            if self.closed
            else "BOUND"
            if self.channel
            else "NOT_OBSERVED",
            frames=self.frames if self.source else None,
            sequence=self.sequence if self.source else None,
            socket_send_failures=self.loss if self.source else None,
            ring_loss=(
                self.counter_evidence["totals"]["ring_reservation_failures"]
                if self.counter_evidence and self.counter_evidence["totals"]
                else None
            ),
            counter_evidence=self.counter_evidence,
            kernel_drops=None,
            queue_overflows=self.queue_overflows,
            backpressure_events=self.backpressure_events,
            queue=self.adapter.metrics() if self.adapter else None,
            processing=self.adapter._summary() if self.adapter else None,
            error=self.error,
            transport_failed=self.transport_failed,
            terminal_closed_observed=self.closed,
            native_ai="BLOCKED",
            automatic_restart=False,
            worker_alive=bool(self.worker and self.worker.is_alive()),
        )
