"""Bounded event-time aggregation over existing FlowTable. No socket or persistence."""

import math
import struct
from dataclasses import dataclass
from uuid import UUID

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    FlowSummary,
    PacketObservation,
)
from soc_agent.security_ai.research.live_input import timestamp_ns


@dataclass
class Statistics:
    first: PacketObservation
    count: int = 0
    forward: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    total: int = 0
    squares: int = 0
    minimum: int = 65535
    maximum: int = 0
    syn: int = 0
    fin: int = 0
    rst: int = 0
    last_ns: int = 0
    iat_sum_ns: int = 0
    iat_max_ns: int = 0

    def add(self, packet: PacketObservation):
        ns = timestamp_ns(packet)
        gap = ns - self.last_ns if self.count else 0
        if gap < 0:
            raise ValueError("STREAM_TIME_REVERSED")
        forward = (packet.source_address, packet.source_port) == (
            self.first.source_address,
            self.first.source_port,
        )
        self.count += 1
        self.forward += int(forward)
        self.forward_bytes += packet.ip_length if forward else 0
        self.backward_bytes += packet.ip_length if not forward else 0
        self.total += packet.ip_length
        self.squares += packet.ip_length**2
        self.minimum = min(self.minimum, packet.ip_length)
        self.maximum = max(self.maximum, packet.ip_length)
        self.syn += bool(packet.tcp_flags & 2)
        self.fin += bool(packet.tcp_flags & 1)
        self.rst += bool(packet.tcp_flags & 4)
        self.iat_sum_ns += gap
        self.iat_max_ns = max(self.iat_max_ns, gap)
        self.last_ns = ns

    def vector(self) -> tuple[float, ...]:
        n = self.count
        # Integer moments avoid drift; parity against the unchanged Producer is
        # checked again for every inferred flow while its packet references exist.
        variance = (self.squares * n - self.total**2) / (n * n)
        values = (
            (self.last_ns - timestamp_ns(self.first)) / 1e9,
            self.forward,
            n - self.forward,
            self.forward_bytes,
            self.backward_bytes,
            self.minimum,
            self.maximum,
            self.total / n,
            math.sqrt(variance),
            self.syn,
            self.fin,
            self.rst,
            self.iat_sum_ns / (n - 1) / 1e9 if n > 1 else 0,
            self.iat_max_ns / 1e9,
        )
        return tuple(struct.unpack("!f", struct.pack("!f", v))[0] for v in values)


@dataclass(frozen=True)
class CompletedFlow:
    flow: FlowSummary
    packets: tuple[PacketObservation, ...]
    identities: tuple[UUID, ...]
    values: tuple[float, ...]


class StreamingFlows:
    """Retain <=128 packet references per flow until independent Producer parity.

    No wall-clock expiry: delivered kernel event time alone advances FlowTable.
    SHUTDOWN/PACKET_LIMIT/RESTART_GAP remain diagnostic. No packet is fabricated.
    """

    def __init__(self, *, max_flows=128, metadata_bytes=8 * 1024**2):
        if not 1 <= max_flows <= 128 or not 8192 <= metadata_bytes <= 16 * 1024**2:
            raise ValueError("STREAM_FLOW_BUDGET_INVALID")
        self.configured_flow_limit = max_flows
        self.table = FlowTable(CaptureConfig(interface="lo", max_flows=max_flows))
        self.packets: dict[str, PacketObservation] = {}
        self.sizes: dict[str, int] = {}
        self.stats: dict[str, Statistics] = {}
        self.bytes = 0
        self.peak_bytes = 0
        self.limit = metadata_bytes
        self.last_ns = None
        self.last_time = None
        self.observed = 0
        self.completed = 0

    def add(self, packet: PacketObservation, identity: UUID) -> list[CompletedFlow]:
        key = str(identity)
        if key in self.packets:
            raise ValueError("STREAM_DUPLICATE_PACKET")
        if self.last_ns is not None and timestamp_ns(packet) < self.last_ns:
            raise ValueError("STREAM_TIME_REVERSED")
        size = len(packet.model_dump_json().encode())
        if self.bytes + size > self.limit:
            raise ValueError("STREAM_METADATA_MEMORY_BACKPRESSURE")
        existing = self.table.flows.get(self.table.key(packet))
        alive = sum(
            timestamp_ns(packet) - timestamp_ns(f.first) < 120_000_000_000
            and timestamp_ns(packet) - timestamp_ns(f.last) < 30_000_000_000
            for f in self.table.flows.values()
        )
        if existing is None and alive >= self.configured_flow_limit:
            raise ValueError("STREAM_ACTIVE_FLOW_BACKPRESSURE")
        first = key
        if existing is not None and (
            timestamp_ns(packet) - timestamp_ns(existing.first) < 120_000_000_000
            and timestamp_ns(packet) - timestamp_ns(existing.last) < 30_000_000_000
        ):
            first = existing.ids[0]
        statistics = self.stats.setdefault(first, Statistics(packet))
        statistics.add(packet)
        self.packets[key] = packet
        self.sizes[key] = size
        self.bytes += size
        self.peak_bytes = max(self.bytes, self.peak_bytes)
        self.last_ns = timestamp_ns(packet)
        self.last_time = packet.timestamp
        self.observed += 1
        return self._complete(self.table.add(packet, key))

    def _complete(self, flows: list[FlowSummary]) -> list[CompletedFlow]:
        result = []
        for flow in flows:
            ids = flow.source_event_ids
            statistics = self.stats.pop(ids[0])
            result.append(
                CompletedFlow(
                    flow,
                    tuple(self.packets.pop(i) for i in ids),
                    tuple(UUID(i) for i in ids),
                    statistics.vector(),
                )
            )
            self.bytes -= sum(self.sizes.pop(i) for i in ids)
            self.completed += 1
        return result

    def close(self, reason="SHUTDOWN") -> list[CompletedFlow]:
        if self.last_time is None:
            return []
        result = self._complete(self.table.expire(self.last_time, reason, now_ns=self.last_ns))
        self.last_ns = self.last_time = None
        return result
