"""Independent bounded metadata transport; never executes a loader or model."""

import array
import os
import queue
import select
import socket
import sqlite3
import struct
import threading
import time
from functools import wraps
from pathlib import Path

from soc_agent.security_ai.ebpf.checkpoint import CheckpointFailure, CheckpointWriter
from soc_agent.security_ai.ebpf.clock import ClockContract
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.models import Plan
from soc_agent.security_ai.ebpf_native.contracts import process_identity
from soc_agent.security_ai.ebpf_tc.contracts import NativePlan

HEADER = struct.Struct("<4IQQ16s32s32s")
CREDENTIAL = struct.Struct("3i")
MAGIC = 0x31445053
ROW_BYTES = HEADER.size + 80
PACKET_ADMISSION_TIMEOUT_SECONDS = 0.05


def synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        started = time.perf_counter_ns()
        with self.lock:
            if method.__name__ == "pump":
                self.receiver_metrics["pump_lock_wait_max_ns"] = max(
                    self.receiver_metrics["pump_lock_wait_max_ns"], time.perf_counter_ns() - started
                )
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
        self.io_failure: dict[str, int | str | None] | None = None
        self.cleanup_error: str | None = None
        self.processing_io_failure: dict | None = None
        self.processor: threading.Thread | None = None
        self.processing_queue: queue.Queue[tuple[bytes, int]] = queue.Queue(maxsize=32)
        # One shared 32-record budget across ingress, in-flight and event-time
        # reorder storage; adding a worker must not double the approved budget.
        self.packet_slots = threading.BoundedSemaphore(32)
        self.processing_idle = threading.Event()
        self.processing_idle.set()
        self.processing_stop = threading.Event()
        self.wire_closed = False
        self.end_pending: bytes | None = None
        self.cached_processing = self.cached_queue = None
        self.processing_discarded = self.processing_queue_peak = 0
        self.receiver_metrics = dict(
            recv_calls=0,
            recv_gap_max_ns=0,
            recv_max_ns=0,
            pump_lock_wait_max_ns=0,
            validation_max_ns=0,
            processing_calls=0,
            processing_max_ns=0,
            queue_wait_max_ns=0,
            queue_full=0,
            admission_waits=0,
            admission_resumed=0,
            admission_timeouts=0,
            admission_wait_total_ns=0,
            admission_wait_max_ns=0,
            receiver_stopped_ns=None,
            close_requested_ns=None,
            closed_received_ns=None,
        )
        self.last_receive_ns: int | None = None

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
        self.processor = threading.Thread(target=self._process, name="tcx-flow-worker", daemon=True)
        self.processor.start()
        self.worker = threading.Thread(
            target=self._consume, name="tcx-metadata-reader", daemon=True
        )
        self.worker.start()

    def _consume(self) -> None:
        while not self.stop_event.is_set() and not self.wire_closed and not self.transport_failed:
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
                break
        self.receiver_metrics["receiver_stopped_ns"] = time.perf_counter_ns()

    def _processing_failure(self, code: str) -> None:
        self.error = self.error or code
        if self.adapter and not self.adapter.flow.closed:
            self.adapter.last_error = self.error
            self.adapter.state = "ERROR"
            try:
                self.adapter.end_metadata_stream("INCOMPLETE")
            except (OSError, sqlite3.Error, CheckpointFailure) as exc:
                self._processing_io_error(exc)

    def _processing_io_error(self, exc: OSError | sqlite3.Error | CheckpointFailure) -> None:
        self.processing_io_failure = self.processing_io_failure or dict(
            api="packet_adapter_or_checkpoint",
            errno=exc.errno if isinstance(exc, OSError) else None,
            sqlite_errorcode=getattr(exc, "sqlite_errorcode", None),
        )
        self.cleanup_error = self.cleanup_error or "TCX_PROCESSING_AUDIT_UNVERIFIED"
        self.error = self.error or self.cleanup_error

    def _publish(self) -> None:
        # Only the processing owner reads the live assembler. GUI/control gets
        # immutable projections and never holds the receive lock across SQLite.
        if self.adapter:
            self.cached_processing = self.adapter._summary()
            self.cached_queue = self.adapter.metrics()

    def _process(self) -> None:
        while True:
            try:
                raw, received_ns = self.processing_queue.get(timeout=0.02)
            except queue.Empty:
                self.processing_idle.clear()
                if self.error:
                    before = len(self.adapter.queue) if self.adapter else 0
                    self._processing_failure(self.error)
                    self._release_slots(before)
                if self.end_pending is not None:
                    end, self.end_pending = self.end_pending, None
                    before = len(self.adapter.queue) if self.adapter else 0
                    try:
                        self._apply(4, end)
                    except (ValueError, OSError, sqlite3.Error) as exc:
                        if not isinstance(exc, ValueError):
                            self._processing_io_error(exc)
                        self._processing_failure(
                            str(exc) if isinstance(exc, ValueError) else self.error
                        )
                    self._release_slots(before - (len(self.adapter.queue) if self.adapter else 0))
                    self._publish()
                if (
                    self.wire_closed or self.processing_stop.is_set()
                ) and self.processing_queue.empty():
                    before = len(self.adapter.queue) if self.adapter else 0
                    if self.adapter and not self.adapter.flow.closed:
                        try:
                            self.adapter.end_metadata_stream(
                                "CAPTURE_STOP" if self.wire_closed else "INCOMPLETE"
                            )
                        except (OSError, sqlite3.Error, ValueError) as exc:
                            if not isinstance(exc, ValueError):
                                self._processing_io_error(exc)
                            self._processing_failure(
                                str(exc) if isinstance(exc, ValueError) else self.error
                            )
                    self._release_slots(before - (len(self.adapter.queue) if self.adapter else 0))
                    self.closed = self.wire_closed
                    self._publish()
                    self.processing_idle.set()
                    return
                self.processing_idle.set()
                continue
            self.processing_idle.clear()
            before = len(self.adapter.queue) if self.adapter else 0
            start = time.perf_counter_ns()
            self.receiver_metrics["queue_wait_max_ns"] = max(
                self.receiver_metrics["queue_wait_max_ns"], start - received_ns
            )
            try:
                if self.error:
                    self._processing_failure(self.error)
                if (
                    self.adapter
                    and self.adapter.checkpoint_writer
                    and self.adapter.checkpoint_writer.failure
                ):
                    raise CheckpointFailure("EBPF_CHECKPOINT_WRITER_FAILED")
                self._apply(2, raw)
            except (ValueError, OSError, sqlite3.Error) as exc:
                if not isinstance(exc, ValueError):
                    self._processing_io_error(exc)
                self._processing_failure(
                    str(exc) if isinstance(exc, ValueError) else "TCX_PROCESSING_IO_FAILURE"
                )
            finally:
                self.receiver_metrics["processing_calls"] += 1
                self.receiver_metrics["processing_max_ns"] = max(
                    self.receiver_metrics["processing_max_ns"], time.perf_counter_ns() - start
                )
                self._release_slots(1 + before - (len(self.adapter.queue) if self.adapter else 0))
                self.processing_queue.task_done()
                if (
                    self.processing_queue.empty()
                    or self.receiver_metrics["processing_calls"] % 32 == 0
                ):
                    self._publish()
                self.processing_idle.set()

    def _release_slots(self, count: int) -> None:
        for _ in range(count):
            self.packet_slots.release()

    @synchronized
    def prepare_adapter(self, generation: int, clock: ClockContract | None = None) -> None:
        if not self.source or self.closed or self.error or self.runs >= 16:
            raise ValueError("TCX_DATA_RUN_DENIED")
        if self.adapter and not self.adapter.flow.closed:
            raise ValueError("TCX_DATA_PREVIOUS_RUN_UNFINISHED")
        if self.adapter and self.adapter.checkpoint_writer:
            if not self.processing_idle.wait(timeout=2):
                raise ValueError("TCX_DATA_PROCESSING_NOT_IDLE")
            self.adapter.checkpoint_writer.close()
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
        if self.processor:
            self.adapter.checkpoint_writer = CheckpointWriter(self.adapter._persist_checkpoint)
        self._publish()

    def _receive(self, *, ready: bool = False) -> None:
        if self.channel is None or self.identity is None or self.closed:
            raise ValueError("TCX_DATA_CHANNEL_NOT_READY")
        # Peek only the fixed header for scheduling. Authentication still happens
        # on the complete recvmsg record below. Reserve before consuming a packet
        # so an admission wait cannot create a 33rd retained packet.
        reserved = False
        transferred = False
        peek_kind = None
        try:
            if self.processor:
                try:
                    prefix = self.channel.recv(16, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                except OSError as exc:
                    self.io_failure = self.io_failure or dict(
                        api="recv(MSG_PEEK)", errno=exc.errno, source="ACTUAL_OSERROR"
                    )
                    raise
                if len(prefix) == 16:
                    peek_kind = struct.unpack("<4I", prefix)[2]
                if peek_kind == 2:
                    reserved = self.packet_slots.acquire(blocking=False)
                    if not reserved and not self.error:
                        started = time.perf_counter_ns()
                        self.receiver_metrics["admission_waits"] += 1
                        reserved = self.packet_slots.acquire(
                            timeout=PACKET_ADMISSION_TIMEOUT_SECONDS
                        )
                        elapsed = time.perf_counter_ns() - started
                        self.receiver_metrics["admission_wait_total_ns"] += elapsed
                        self.receiver_metrics["admission_wait_max_ns"] = max(
                            self.receiver_metrics["admission_wait_max_ns"], elapsed
                        )
                        self.receiver_metrics[
                            "admission_resumed" if reserved else "admission_timeouts"
                        ] += 1
            transferred = self._receive_record(ready=ready, reserved=reserved, peek_kind=peek_kind)
        finally:
            if reserved and not transferred:
                self.packet_slots.release()

    def _receive_record(self, *, ready: bool, reserved: bool, peek_kind: int | None) -> bool:
        try:
            before = time.perf_counter_ns()
            if self.last_receive_ns is not None:
                self.receiver_metrics["recv_gap_max_ns"] = max(
                    self.receiver_metrics["recv_gap_max_ns"], before - self.last_receive_ns
                )
            body, ancillary, flags, _ = self.channel.recvmsg(
                ROW_BYTES + 1, socket.CMSG_SPACE(64), socket.MSG_CMSG_CLOEXEC
            )
            self.last_receive_ns = time.perf_counter_ns()
            self.receiver_metrics["recv_calls"] += 1
            self.receiver_metrics["recv_max_ns"] = max(
                self.receiver_metrics["recv_max_ns"], self.last_receive_ns - before
            )
        except OSError as exc:
            self.io_failure = self.io_failure or dict(
                api="recvmsg", errno=exc.errno, source="ACTUAL_OSERROR"
            )
            raise
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
        missing = sequence - (0 if ready else self.sequence + 1)
        if missing != loss - self.loss or missing < 0 or sequence > 65568:
            raise ValueError("TCX_DATA_SEQUENCE_OR_COUNTER_RESET")
        if kind not in ({1} if ready else {2, 3, 4, 5}):
            raise ValueError("TCX_DATA_KIND")
        if self.processor and peek_kind != kind:
            raise ValueError("TCX_DATA_PEEK_KIND_CHANGED")
        self.sequence, self.loss = sequence, loss
        self.frames += 1
        if loss:
            # Authenticated sender-declared loss stops feature processing, but
            # counter/terminal records still have valid identity and sequence.
            self.error = self.error or "TCX_DATA_SOCKET_DELIVERY_LOSS"
        self.receiver_metrics["validation_max_ns"] = max(
            self.receiver_metrics["validation_max_ns"],
            time.perf_counter_ns() - self.last_receive_ns,
        )
        raw = body[HEADER.size :]
        if self.processor and kind == 2:
            try:
                if not reserved:
                    raise queue.Full
                self.processing_queue.put_nowait((raw, time.perf_counter_ns()))
                self.processing_queue_peak = max(
                    self.processing_queue_peak, self.processing_queue.qsize()
                )
                return True
            except queue.Full:
                self.receiver_metrics["queue_full"] += 1
                self.processing_discarded += 1
                self.error = self.error or "TCX_PROCESSING_QUEUE_OVERFLOW"
            return False
        if self.processor and kind == 4:
            if self.end_pending is not None:
                raise ValueError("TCX_DATA_DUPLICATE_END")
            self.end_pending = raw
            return False
        if self.processor and kind == 3:
            if any(raw):
                raise ValueError("TCX_DATA_CONTROL_SCHEMA")
            self.wire_closed = True
            self.receiver_metrics["closed_received_ns"] = time.perf_counter_ns()
            return False
        self._apply(kind, raw)
        return False

    def _apply(self, kind: int, raw: bytes) -> None:
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
        if self.worker and threading.current_thread() is not self.worker:
            if self.error:
                raise ValueError(self.error)
            return 0
        count = 0
        try:
            while (
                self.channel
                and not self.closed
                and not self.wire_closed
                and count < limit
                and select.select([self.channel], [], [], 0)[0]
            ):
                self._receive()
                count += 1
            if not self.processor and self.adapter and self.adapter.queue:
                self.adapter.drain()
        except (ValueError, OSError) as exc:
            code = str(exc) if isinstance(exc, ValueError) else "TCX_DATA_IO_FAILURE"
            self.error = self.error or code
            recoverable = {
                "EBPF_CLOCK_INVALID",
                "EBPF_REORDER_LATE_CAPTURE_GAP",
                "EBPF_QUEUE_OVERFLOW_CAPTURE_GAP",
                "EBPF_CPU_SEQUENCE_GAP_OR_REUSE",
            }
            self.transport_failed = code not in recoverable
            self.queue_overflows += int(self.error == "EBPF_QUEUE_OVERFLOW_CAPTURE_GAP")
            if self.adapter and not self.processor:
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
        self.receiver_metrics["close_requested_ns"] = time.perf_counter_ns()
        if self.worker:
            deadline = time.monotonic() + 2
            while (
                self.worker.is_alive()
                and not self.wire_closed
                and not self.transport_failed
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=2)
            if self.worker.is_alive():
                self.cleanup_error = "TCX_DATA_WORKER_SHUTDOWN_UNVERIFIED"
                self.error = self.error or self.cleanup_error
        try:
            if self.channel and not self.transport_failed and not self.worker:
                # Bounded final drain, not an unbounded EOF wait or auto-restart.
                for _ in range(2050):
                    if self.closed or not self.pump():
                        break
            if self.processor:
                self.processing_stop.set()
                self.processor.join(timeout=2)
                if not self.wire_closed:
                    self.cleanup_error = "TCX_DATA_TERMINAL_UNVERIFIED"
                    self.error = self.error or self.cleanup_error
                if self.processor.is_alive():
                    self.cleanup_error = "TCX_PROCESSOR_SHUTDOWN_UNVERIFIED"
                    self.error = self.error or self.cleanup_error
            if (
                self.adapter
                and not self.adapter.flow.closed
                and not (self.processor and self.processor.is_alive())
            ):
                self.adapter.end_metadata_stream("INCOMPLETE")
            if self.adapter and not (self.processor and self.processor.is_alive()):
                try:
                    if self.adapter.checkpoint_writer:
                        self.adapter.checkpoint_writer.flush()
                    self.adapter.checkpoint()
                except (OSError, sqlite3.Error, CheckpointFailure) as exc:
                    self._processing_io_error(exc)
                self._publish()
        finally:
            if self.adapter and self.adapter.checkpoint_writer:
                try:
                    self.adapter.checkpoint_writer.close()
                except CheckpointFailure as exc:
                    self._processing_io_error(exc)
                self._publish()
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
            queue=self.cached_queue
            if self.processor
            else self.adapter.metrics()
            if self.adapter
            else None,
            processing=self.cached_processing
            if self.processor
            else self.adapter._summary()
            if self.adapter
            else None,
            receiver=dict(self.receiver_metrics),
            processing_queue=dict(
                capacity=32,
                budget="SHARED_INGRESS_INFLIGHT_AND_REORDER",
                depth=self.processing_queue.qsize(),
                peak=self.processing_queue_peak,
                discarded=self.processing_discarded,
            ),
            error=self.error,
            transport_failed=self.transport_failed,
            io_failure=self.io_failure,
            processing_io_failure=self.processing_io_failure,
            cleanup_error=self.cleanup_error,
            terminal_closed_observed=self.wire_closed if self.processor else self.closed,
            native_ai="BLOCKED",
            automatic_restart=False,
            worker_alive=bool(self.worker and self.worker.is_alive()),
            processor_alive=bool(self.processor and self.processor.is_alive()),
            processing_pending=self.processing_queue.unfinished_tasks,
            audit_writer=self.adapter.checkpoint_writer.snapshot()
            if self.adapter and self.adapter.checkpoint_writer
            else None,
            drain_state="FAILED"
            if self.error or self.cleanup_error
            else "PENDING"
            if not self.closed
            or self.processing_queue.unfinished_tasks
            or self.worker
            and self.worker.is_alive()
            or self.processor
            and self.processor.is_alive()
            or self.adapter
            and self.adapter.checkpoint_writer
            and (
                self.adapter.checkpoint_writer.worker.is_alive()
                or self.adapter.checkpoint_writer.submitted
                != self.adapter.checkpoint_writer.committed
            )
            else "VERIFIED",
        )
