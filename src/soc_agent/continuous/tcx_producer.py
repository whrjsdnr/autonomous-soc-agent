"""Continuous TCX receiver and ABI adapter; Root entry and diagnostic gates are separate."""

import asyncio
import ipaddress
import json
import socket
import struct
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

    async def receive_message(self, loop):
        """Keep the five-second fail-closed deadline and preserve its exact stage."""
        try:
            return await asyncio.wait_for(loop.sock_recv(self.socket, 262145), 5)
        except TimeoutError as error:
            import time

            self.failure = dict(
                code="CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT",
                stage="AUTHENTICATED_ROOT_RECEIVE",
                timeout_seconds=5,
                last_message_unix=self.last_message_unix,
                last_message_age_seconds=(time.time() - self.last_message_unix)
                if self.last_message_unix is not None
                else None,
                generation=self.epoch,
                last_sequence=self.last_sequence,
                capture_restarted=False,
            )
            raise ValueError("CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT") from error

    async def events(self):
        import os

        policy = installed()
        if policy["uid"] != os.getuid() or policy["namespace"] != self.config.namespace:
            raise ValueError("CONTINUOUS_PRODUCER_POLICY_SCOPE")
        self.state = "STARTING"
        self.last_message_unix = None
        self.stop_ack.clear()
        self.remote_cleanup = "UNKNOWN"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.socket.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.sock_connect(self.socket, f"/run/soc-agent-continuous/{os.getuid()}.sock"), 5
            )
            if (
                struct.unpack(
                    "3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )[1]
                != 0
            ):
                raise ValueError("CONTINUOUS_PRODUCER_ROOT_PEER_REQUIRED")
        except BaseException:
            await self.close()
            raise
        self.state = "RUNNING"
        sequence = 0
        window_sequence = 0
        try:
            while True:
                body = await self.receive_message(loop)
                if not body:
                    raise ValueError("CONTINUOUS_PRODUCER_DISCONNECTED")
                if len(body) > 262144:
                    raise ValueError("CONTINUOUS_PRODUCER_RECORD_BOUND")
                raw = json.loads(body)
                if raw.get("contract") == "soc-continuous-tcx-stop:v1":
                    if (
                        raw.get("namespace") != policy["namespace"]
                        or raw.get("generation") != (self.epoch or self.sealed_epoch)
                        or raw.get("policy_sha256") != self.config.input_sha256
                    ):
                        raise ValueError("CONTINUOUS_STOP_ACK_BINDING")
                    self.remote_cleanup = raw.get("cleanup", "UNKNOWN")
                    self.stop_ack.set()
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
                ClockSample(
                    before_ns=raw["clock"][0], wall_ns=raw["clock"][1], after_ns=raw["clock"][2]
                )
                self.state = raw["state"]["state"]
                if self.state not in ("RUNNING", "DEGRADED") and not (
                    self.state == "SEALED" and raw.get("seal") is not None
                ):
                    raise ValueError("CONTINUOUS_PRODUCER_NOT_RUNNING")
                self.epoch = raw["generation"]
                # Readiness is control-plane identity, not proof of packet delivery.
                # A quiet attached Collector legitimately has no per-CPU counters.
                self.snapshot = dict(raw["state"], generation=self.epoch)
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
                import time

                self.last_message_unix = time.time()
                for frame in raw["frames"]:
                    sequence += 1
                    window_sequence += 1
                    self.received += 1
                    identity = str(uuid5(NAMESPACE_URL, f"{self.epoch}:{sequence}:{frame}"))
                    yield dict(
                        kind="native_tcx",
                        id=identity,
                        sequence=sequence,
                        wire_hex=frame,
                        window_sequence=window_sequence,
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
                    sequence += 1
                    yield dict(
                        kind="native_seal",
                        id=str(uuid5(NAMESPACE_URL, seal.identity)),
                        sequence=sequence,
                        seal=seal.model_dump(mode="json"),
                    )
                    self.sealed_epoch = self.epoch
                    self.epoch = None
                    self.cpus = {}
                    window_sequence = 0
        finally:
            await self.close()

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
            if self.epoch is not None:
                break
            await asyncio.sleep(0.05)
        if self.epoch is None:
            raise ValueError("CONTINUOUS_STOP_REQUIRES_CONNECTED_OWNER")
        body = json.dumps(
            dict(
                operation="STOP_CAPTURE",
                generation=self.epoch,
                policy_sha256=self.config.input_sha256,
            )
        ).encode()
        await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(self.socket, body), 2)
        await asyncio.wait_for(self.stop_ack.wait(), 5)
        if self.remote_cleanup != "VERIFIED":
            raise ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED")

    async def close(self):
        self.state = "STOPPING"
        if self.socket:
            self.socket.close()
            self.socket = None
        self.state = "STOPPED"
        self.snapshot = self.snapshot | dict(
            state="STOPPED",
            failure=self.failure,
            cleanup=self.remote_cleanup,
        )
