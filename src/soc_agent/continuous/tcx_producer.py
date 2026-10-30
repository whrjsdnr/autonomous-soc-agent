"""Continuous TCX receiver and ABI adapter; Root entry and diagnostic gates are separate."""

import asyncio
import ipaddress
import json
import os
import socket
import struct
import time
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field

from soc_agent.continuous.native.policy import installed
from soc_agent.security_ai.ebpf.models import Counters, Event
from soc_agent.security_ai.ebpf.ring import ABI
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.research.models import digest


class ContinuousEvent(Event):
    """Same TCX payload schema, independent service sequence (no diagnostic authority)."""

    delivery_sequence: int = Field(ge=1, lt=2**63, strict=True)


def decode(
    raw: bytes, *, namespace: str, session, program: str, sequence: int, clock="KERNEL_MONOTONIC_NS"
) -> ContinuousEvent:
    if len(raw) != ABI.size:
        raise ValueError("CONTINUOUS_TCX_ABI_BOUND")
    (
        generation,
        stamp,
        cpu_seq,
        index,
        cpu,
        frame,
        length,
        sport,
        dport,
        family,
        proto,
        flags,
        hook,
        src,
        dst,
    ) = ABI.unpack(raw)
    if (
        family not in (4, 6)
        or proto not in (6, 17)
        or hook != 1
        or (family == 4 and (any(src[4:]) or any(dst[4:])))
    ):
        raise ValueError("CONTINUOUS_TCX_ABI_SCOPE")
    return ContinuousEvent(
        collector="EBPF_TCX",
        session_id=session,
        program_sha256=program,
        plan_digest=digest(dict(mode="CONTINUOUS", namespace=namespace, program=program)),
        generation=generation,
        ifindex=index,
        cpu=cpu,
        cpu_sequence=cpu_seq,
        net_namespace=namespace,
        hook="INGRESS",
        delivery_sequence=sequence,
        timestamp_ns=stamp,
        clock=clock,
        source=str(ipaddress.ip_address(src[:4] if family == 4 else src)),
        destination=str(ipaddress.ip_address(dst[:4] if family == 4 else dst)),
        source_port=sport,
        destination_port=dport,
        protocol="tcp" if proto == 6 else "udp",
        frame_length=frame,
        ip_length=length,
        tcp_flags=flags,
    )


def replay_wire(packet: PacketObservation, timestamp_ns: int, sequence: int) -> bytes:
    """Metadata encoding for actual offline PCAP; not a Kernel event or Native proof."""
    a, b = packet.source_address, packet.destination_address
    return ABI.pack(
        1,
        timestamp_ns,
        sequence,
        1,
        0,
        packet.frame_length,
        packet.ip_length,
        packet.source_port,
        packet.destination_port,
        a.version,
        6 if packet.transport == "tcp" else 17,
        packet.tcp_flags,
        1,
        a.packed.ljust(16, b"\0"),
        b.packed.ljust(16, b"\0"),
    )


def replay_packet(event: ContinuousEvent, interface: str) -> PacketObservation:
    if event.clock != "FIXTURE_PCAP_EVENT_NS":
        raise ValueError("CONTINUOUS_MONOTONIC_IS_NOT_UTC")
    return PacketObservation(
        interface_id=interface,
        timestamp=datetime.fromtimestamp(event.timestamp_ns // 10**9, UTC).replace(
            microsecond=event.timestamp_ns % 10**9 // 1000
        ),
        timestamp_origin="FIXTURE",
        direction="UNKNOWN",
        source_address=event.source,
        destination_address=event.destination,
        source_port=event.source_port,
        destination_port=event.destination_port,
        transport=event.protocol,
        frame_length=event.frame_length,
        ip_length=event.ip_length,
        tcp_flags=event.tcp_flags,
        ip_version=event.source.version,
        header_length=(40 if event.source.version == 6 else 20)
        + (20 if event.protocol == "tcp" else 8),
        raw_frame_digest=digest(event.model_dump(mode="json")),
    )


class TCXProducer:
    """Read only from the installed fixed Root socket; never launch or authenticate Root."""

    def __init__(self, config):
        self.config = config
        self.socket = None
        self.state = "STOPPED"
        self.received = 0
        self.epoch = None
        self.last_sequence = None
        self.snapshot = {}
        self.cpus = {}
        self.stop_ack = asyncio.Event()
        self.remote_cleanup = "UNKNOWN"
        self.sealed_epoch = None
        self.last_message_unix = None
        self.failure = None
        self.receiver_queue_depth = 0
        self.receiver_dropped_batches = 0
        self.last_message_monotonic = None
        self.last_data_monotonic = None
        self.peer_identity = None
        self._event_sequence = 0
        self._window_sequence = 0
        self._cleanup_pending = []
        self._stop_sent = False
        self._stop_lock = asyncio.Lock()
        self.last_validated_monotonic = None
        self.last_root_clock = None
        self._entered = False
        self.cleanup_evidence = dict(
            status="NOT_STARTED",
            stop_ack=False,
            seals=[],
            quarantined_events=0,
        )

    def envelope(self, body, policy):
        """Authenticate transport scope before freshness; never feature eligibility."""
        if not body:
            raise ValueError("CONTINUOUS_PRODUCER_DISCONNECTED")
        if len(body) > 262144:
            raise ValueError("CONTINUOUS_PRODUCER_RECORD_BOUND")
        raw = json.loads(body)
        if not isinstance(raw, dict):
            raise ValueError("CONTINUOUS_PRODUCER_IDENTITY")
        contract = raw.get("contract")
        if contract not in ("soc-continuous-tcx:v1", "soc-continuous-tcx-stop:v1"):
            raise ValueError("CONTINUOUS_PRODUCER_IDENTITY")
        if raw.get("namespace") != policy["namespace"]:
            raise ValueError("CONTINUOUS_PRODUCER_IDENTITY")
        if (
            contract == "soc-continuous-tcx-stop:v1"
            and raw.get("policy_sha256") != self.config.input_sha256
        ):
            raise ValueError("CONTINUOUS_STOP_ACK_BINDING")
        if contract == "soc-continuous-tcx:v1" and (
            raw.get("ifindex") != 1
            or raw.get("program_sha256") != policy["files"]["continuous.bpf.o"]
        ):
            raise ValueError("CONTINUOUS_PRODUCER_IDENTITY")
        return raw

    async def messages(self, loop, policy):
        """Receive authenticated bounded envelopes independently of durable projection.

        A slow event consumer must not stop reading quiet control heartbeats.
        Capacity remains bounded; overflow fails the stream and cannot attest a
        complete window. No Kernel restart or timeout extension is performed.
        """
        queue = asyncio.Queue(maxsize=self.config.queue_capacity)

        async def receive():
            while True:
                body = await self.receive_message(loop)
                raw = self.envelope(body, policy)
                self.last_message_unix = time.time()
                self.last_message_monotonic = time.monotonic()
                if raw.get("frames"):
                    self.last_data_monotonic = self.last_message_monotonic
                try:
                    queue.put_nowait(raw)
                except asyncio.QueueFull as error:
                    self.receiver_dropped_batches += 1
                    self.failure = dict(
                        code="CONTINUOUS_PRODUCER_RECEIVER_QUEUE_FULL",
                        stage="AUTHENTICATED_ROOT_HANDOFF",
                        capacity=self.config.queue_capacity,
                        dropped_batches=self.receiver_dropped_batches,
                        capture_restarted=False,
                    )
                    raise ValueError("CONTINUOUS_PRODUCER_RECEIVER_QUEUE_FULL") from error
                self.receiver_queue_depth = queue.qsize()
                if raw["contract"] == "soc-continuous-tcx-stop:v1":
                    return

        reader = asyncio.create_task(receive())
        pending = None
        try:
            while True:
                if reader.done():
                    reader.result()  # A failure takes precedence over queued partial evidence.
                    if queue.empty():
                        return
                pending = asyncio.create_task(queue.get())
                await asyncio.wait((pending, reader), return_when=asyncio.FIRST_COMPLETED)
                if reader.done():
                    reader.result()
                raw = await pending
                pending = None
                self.receiver_queue_depth = queue.qsize()
                yield raw
        finally:
            if pending is not None:
                pending.cancel()
            reader.cancel()
            await asyncio.gather(reader, *([pending] if pending else []), return_exceptions=True)
            # Retain bounded, already authenticated envelopes for STOP evidence only.
            if pending and pending.done() and not pending.cancelled() and not pending.exception():
                self._cleanup_pending.append(pending.result())
            while not queue.empty():
                self._cleanup_pending.append(queue.get_nowait())
            self.receiver_queue_depth = 0
            self.cleanup_evidence["receiver_joined"] = True

    async def receive_message(self, loop):
        """Keep the five-second fail-closed deadline and preserve its exact stage."""
        started = time.monotonic()
        try:
            return await asyncio.wait_for(loop.sock_recv(self.socket, 262145), 5)
        except TimeoutError as error:
            now = time.monotonic()
            self.failure = self.failure or dict(
                code="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT",
                stage="AUTHENTICATED_ROOT_RECEIVE",
                timeout_seconds=5,
                last_message_unix=self.last_message_unix,
                last_message_age_seconds=(time.time() - self.last_message_unix)
                if self.last_message_unix is not None
                else None,
                last_message_monotonic=self.last_message_monotonic,
                last_validated_monotonic=self.last_validated_monotonic,
                last_root_clock=self.last_root_clock,
                last_message_age_monotonic_seconds=(now - self.last_message_monotonic)
                if self.last_message_monotonic is not None
                else None,
                last_data_age_monotonic_seconds=(now - self.last_data_monotonic)
                if self.last_data_monotonic is not None
                else None,
                wait_elapsed_seconds=now - started,
                observed_unix=time.time(),
                observed_monotonic=now,
                peer=self.peer_observation(),
                ipc_connected=self.socket is not None and self.socket.fileno() >= 0,
                receiver_queue_depth=self.receiver_queue_depth,
                receiver_dropped_batches=self.receiver_dropped_batches,
                generation=self.epoch,
                last_sequence=self.last_sequence,
                capture_restarted=False,
            )
            raise ValueError("CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT") from error

    async def connect(self, loop):
        """Fixed installed Root endpoint; the only privileged transport boundary."""
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.socket.setblocking(False)
        try:
            await asyncio.wait_for(
                loop.sock_connect(self.socket, f"/run/soc-agent-continuous/{os.getuid()}.sock"), 5
            )
            pid, uid, gid = struct.unpack(
                "3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != 0:
                raise ValueError("CONTINUOUS_PRODUCER_ROOT_PEER_REQUIRED")
            from soc_agent.security_ai.operational.network_capture.live_helper import process_start

            self.peer_identity = dict(pid=pid, uid=uid, gid=gid, start_ticks=process_start(pid))
        except BaseException:
            await self.close()
            raise

    async def events(self):
        if self._entered:
            raise ValueError("CONTINUOUS_PRODUCER_SESSION_REUSE_FORBIDDEN")
        self._entered = True
        policy = installed()
        if policy["uid"] != os.getuid() or policy["namespace"] != self.config.namespace:
            raise ValueError("CONTINUOUS_PRODUCER_POLICY_SCOPE")
        self.state = "STARTING"
        self.last_message_unix = None
        self.stop_ack.clear()
        self.remote_cleanup = "UNKNOWN"
        loop = asyncio.get_running_loop()
        await self.connect(loop)
        self.state = "RUNNING"
        messages = self.messages(loop, policy)
        try:
            async for raw in messages:
                for event in self.records(raw, policy):
                    # A failure can arrive while the consumer durably projects
                    # an earlier frame from this same batch. Admit no tail.
                    if self.failure:
                        self.quarantine(event)
                    else:
                        yield event
                if self.failure:
                    raise ValueError(self.failure["code"])
        except BaseException as error:
            import traceback

            self.failure = self.failure or dict(
                code=str(error) or type(error).__name__,
                category=type(error).__name__,
                stage="AUTHENTICATED_ROOT_PROTOCOL",
                observed_unix=time.time(),
                observed_monotonic=time.monotonic(),
                capture_restarted=False,
            )
            self.failure.setdefault(
                "origin",
                [
                    dict(file=os.path.basename(r.filename), function=r.name, line=r.lineno)
                    for r in traceback.extract_tb(error.__traceback__)[-8:]
                ],
            )
            self.state = "DEGRADED"
            self.snapshot = self.snapshot | dict(state=self.state, failure=self.failure)
            raise
        finally:
            try:
                await messages.aclose()
                if self.failure and not self.stop_ack.is_set():
                    await self.cleanup_failed_stream(loop, policy)
            finally:
                await self.close()

    def records(self, raw, policy):
        """The same sequence/epoch/counter/seal validator serves both readers."""
        if raw.get("contract") == "soc-continuous-tcx-stop:v1":
            if (
                raw.get("namespace") != policy["namespace"]
                or raw.get("generation") != (self.epoch or self.sealed_epoch)
                or raw.get("policy_sha256") != self.config.input_sha256
            ):
                raise ValueError("CONTINUOUS_STOP_ACK_BINDING")
            self.remote_cleanup = raw.get("cleanup", "UNKNOWN")
            self.stop_ack.set()
            self.cleanup_evidence.update(
                stop_ack=True,
                ack_observed_unix=time.time(),
                ack=dict(raw),
                status="VERIFIED" if self.remote_cleanup == "VERIFIED" else "UNVERIFIED",
                scope="BOUND_TCX_ACK_NOT_GLOBAL_KERNEL_CLEANUP",
            )
            return
        if (
            raw["contract"] != "soc-continuous-tcx:v1"
            or raw["namespace"] != policy["namespace"]
            or raw["ifindex"] != 1
            or raw["program_sha256"] != policy["files"]["continuous.bpf.o"]
            or type(raw["generation"]) is not int
            or not 0 < raw["generation"] < 2**64
        ):
            raise ValueError("CONTINUOUS_PRODUCER_IDENTITY")
        if self.last_sequence is not None and raw["sequence"] != self.last_sequence + 1:
            raise ValueError("CONTINUOUS_PRODUCER_SEQUENCE_GAP")
        self.last_sequence = raw["sequence"]
        if self.epoch is not None and self.epoch != raw["generation"]:
            raise ValueError("CONTINUOUS_PRODUCER_EPOCH_CHANGED")
        from soc_agent.security_ai.ebpf.clock import ClockSample

        if len(raw["frames"]) > 32 or len(raw["state"]["counters"]) > 8192:
            raise ValueError("CONTINUOUS_PRODUCER_BATCH_BOUND")
        ClockSample(before_ns=raw["clock"][0], wall_ns=raw["clock"][1], after_ns=raw["clock"][2])
        self.state = raw["state"]["state"]
        if self.state not in ("RUNNING", "DEGRADED") and not (
            self.state == "SEALED" and raw.get("seal") is not None
        ):
            raise ValueError("CONTINUOUS_PRODUCER_NOT_RUNNING")
        self.epoch = raw["generation"]
        # Readiness is control-plane identity, not proof of packet delivery.
        # A quiet attached Collector legitimately has no per-CPU counters.
        self.snapshot = dict(raw["state"], generation=self.epoch, failure=self.failure)
        for cpu, values in raw["state"]["counters"].items():
            checked = Counters(
                generation=self.epoch,
                hook="INGRESS",
                cpu=int(cpu),
                **dict(
                    zip(
                        (
                            "observed",
                            "emitted",
                            "ring_lost",
                            "unsupported",
                            "malformed",
                            "disabled",
                            "budget",
                        ),
                        values,
                        strict=True,
                    )
                ),
            )
            old = self.cpus.get(cpu)
            if old and any(a < b for a, b in zip(values, old, strict=True)):
                raise ValueError("CONTINUOUS_PRODUCER_COUNTER_REGRESSION")
            self.cpus[cpu] = list(values)
            self.snapshot["counter_state"] = checked.model_dump(mode="json")
        for frame in raw["frames"]:
            self._event_sequence += 1
            self._window_sequence += 1
            self.received += 1
            identity = str(uuid5(NAMESPACE_URL, f"{self.epoch}:{self._event_sequence}:{frame}"))
            yield dict(
                kind="native_tcx",
                id=identity,
                sequence=self._event_sequence,
                wire_hex=frame,
                window_sequence=self._window_sequence,
                session=str(uuid5(NAMESPACE_URL, str(self.epoch))),
                namespace=policy["namespace"],
                program=raw["program_sha256"],
                transport=raw["state"],
                clock=raw["clock"],
            )
        if raw.get("seal") is not None:
            from soc_agent.continuous.capture import CaptureSeal

            seal = CaptureSeal.model_validate(raw["seal"])
            seal.check()
            if (
                seal.generation != self.epoch
                or seal.namespace != policy["namespace"]
                or seal.policy_sha256 != self.config.input_sha256
                or seal.program_sha256 != raw["program_sha256"]
                or seal.release_manifest != digest(policy["files"])
            ):
                raise ValueError("CONTINUOUS_PRODUCER_SEAL_BINDING")
            self._event_sequence += 1
            yield dict(
                kind="native_seal",
                id=str(uuid5(NAMESPACE_URL, seal.identity)),
                sequence=self._event_sequence,
                seal=seal.model_dump(mode="json"),
            )
            self.sealed_epoch = self.epoch
            self.epoch = None
            self.cpus = {}
            self._window_sequence = 0
        self.last_validated_monotonic = time.monotonic()
        self.last_root_clock = list(raw["clock"])

    def peer_observation(self):
        """Read-only PID/start identity, independent of packet or IPC progress."""
        from soc_agent.security_ai.operational.network_capture.live_helper import process_start

        if self.peer_identity is None:
            return dict(state="UNKNOWN")
        value = dict(self.peer_identity)
        try:
            value["state"] = (
                "SAME_PROCESS"
                if process_start(value["pid"]) == value["start_ticks"]
                else "PID_REUSED"
            )
        except (OSError, ValueError):
            value["state"] = "UNOBSERVABLE"
        return value

    async def cleanup_failed_stream(self, loop, policy):
        """One bounded STOP exchange on the authenticated channel, never reconnect.

        Late events/seals are quarantined as diagnostic evidence. They cannot
        enter the Runtime queue or authorize inference after a failed stream.
        """
        proof = self.cleanup_evidence
        proof.update(
            status="DRAINING",
            first_error=self.failure,
            started_unix=time.time(),
            started_monotonic=time.monotonic(),
            admission="BLOCKED_FAILED_STREAM",
            global_kernel_cleanup="UNKNOWN",
        )
        self.state = "STOPPING"
        try:
            async with asyncio.timeout(5):
                for _ in range(64 + self.config.queue_capacity):
                    # Consume already received control envelopes before choosing
                    # the epoch. A rotation seal must not cause an old STOP to
                    # target a newly advertised owned generation.
                    if not self._cleanup_pending and self.epoch is not None:
                        await self.send_stop(loop)
                    raw = (
                        self._cleanup_pending.pop(0)
                        if self._cleanup_pending
                        else self.envelope(await loop.sock_recv(self.socket, 262145), policy)
                    )
                    for event in self.records(raw, policy):
                        self.quarantine(event)
                    if self.stop_ack.is_set():
                        break
                else:
                    raise ValueError("CONTINUOUS_CLEANUP_MESSAGE_BOUND")
                if not self.stop_ack.is_set() or self.remote_cleanup != "VERIFIED":
                    raise ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED")
                proof["status"] = "VERIFIED"
        except asyncio.CancelledError:
            proof.update(
                status="UNVERIFIED",
                error=dict(
                    code="CONTINUOUS_CLEANUP_CANCELLED",
                    stage="FAILED_STREAM_STOP_DRAIN",
                    category="CancelledError",
                ),
            )
            raise
        except (TimeoutError, ValueError, OSError, KeyError, TypeError) as error:
            import traceback

            proof.update(
                status="UNVERIFIED",
                error=dict(
                    code=str(error) or "CONTINUOUS_STOP_ACK_TIMEOUT",
                    category=type(error).__name__,
                    stage="FAILED_STREAM_STOP_DRAIN",
                    origin=[
                        dict(file=os.path.basename(r.filename), function=r.name, line=r.lineno)
                        for r in traceback.extract_tb(error.__traceback__)[-8:]
                    ],
                ),
            )
        finally:
            proof.update(
                stop_ack=self.stop_ack.is_set(),
                remote_cleanup=self.remote_cleanup,
                completed_unix=time.time(),
                elapsed_seconds=time.monotonic() - proof["started_monotonic"],
            )
            self.snapshot = self.snapshot | dict(failure=self.failure, cleanup_evidence=proof)

    def quarantine(self, event):
        if event["kind"] == "native_seal":
            if len(self.cleanup_evidence["seals"]) >= 2:
                raise ValueError("CONTINUOUS_CLEANUP_SEAL_BOUND")
            self.cleanup_evidence["seals"].append(event["seal"])
        else:
            self.cleanup_evidence["quarantined_events"] += 1

    async def send_stop(self, loop):
        async with self._stop_lock:
            if self._stop_sent:
                return
            if self.socket is None or self.epoch is None:
                raise ValueError("CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER")
            body = json.dumps(
                dict(
                    operation="STOP_CAPTURE",
                    generation=self.epoch,
                    policy_sha256=self.config.input_sha256,
                )
            ).encode()
            await asyncio.wait_for(loop.sock_sendall(self.socket, body), 2)
            self._stop_sent = True
            self.cleanup_evidence["stop_requested_unix"] = time.time()

    async def request_stop(self):
        # A bound STOP ACK remains proof after events() closes the owned socket.
        if self.stop_ack.is_set():
            if self.remote_cleanup != "VERIFIED":
                raise ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED")
            return
        if self.socket is None:
            raise ValueError("CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER")
        # Rotation seals the old epoch before advertising the next. Never send
        # an old epoch STOP to a newly attached owned program.
        for _ in range(50):
            if self.stop_ack.is_set():
                if self.remote_cleanup != "VERIFIED":
                    raise ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED")
                return
            if self.epoch is not None:
                break
            await asyncio.sleep(0.05)
        if self.epoch is None:
            raise ValueError("CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER")
        await self.send_stop(asyncio.get_running_loop())
        await asyncio.wait_for(self.stop_ack.wait(), 5)
        if self.remote_cleanup != "VERIFIED":
            raise ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED")

    async def close(self):
        self.state = "STOPPING"
        if self.socket:
            self.socket.close()
            self.socket = None
        self.state = "STOPPED"
        self.cleanup_evidence["socket_closed"] = self.socket is None
        self.snapshot = self.snapshot | dict(
            state="STOPPED",
            failure=self.failure,
            cleanup=self.remote_cleanup,
            receiver_queue_depth=self.receiver_queue_depth,
            receiver_dropped_batches=self.receiver_dropped_batches,
            cleanup_evidence=self.cleanup_evidence,
        )
