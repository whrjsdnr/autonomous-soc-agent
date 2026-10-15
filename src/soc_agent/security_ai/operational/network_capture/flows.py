"""First-observed bidirectional diagnostic flows, explicitly not CICFlowMeter features."""

from dataclasses import dataclass, field
from datetime import datetime

from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    FlowSummary,
    PacketObservation,
)


@dataclass
class Flow:
    first: PacketObservation
    last: PacketObservation
    ids: list[str] = field(default_factory=list)
    forward: int = 0
    backward: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    total: int = 0
    minimum: int = 65535
    maximum: int = 0
    flags: dict[str, int] = field(default_factory=dict)

    def add(self, packet: PacketObservation, event_id: str):
        if event_id in self.ids:
            return
        if packet.timestamp < self.last.timestamp:
            raise ValueError("PACKET_TIME_REVERSED")
        forward = (packet.source_address, packet.source_port) == (
            self.first.source_address,
            self.first.source_port,
        )
        self.forward += int(forward)
        self.backward += int(not forward)
        self.forward_bytes += packet.frame_length if forward else 0
        self.backward_bytes += packet.frame_length if not forward else 0
        self.total += packet.frame_length
        self.minimum = min(self.minimum, packet.frame_length)
        self.maximum = max(self.maximum, packet.frame_length)
        for bit, name in enumerate(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS")):
            self.flags[name] = self.flags.get(name, 0) + int(bool(packet.tcp_flags & (1 << bit)))
        self.ids.append(event_id)
        self.last = packet

    def summary(self, reason: str) -> FlowSummary:
        p = self.first
        return FlowSummary(
            flow_id=content_digest_payload({"first_event": self.ids[0]}),
            interface_id=p.interface_id,
            source_address=p.source_address,
            destination_address=p.destination_address,
            source_port=p.source_port,
            destination_port=p.destination_port,
            transport=p.transport,
            started_at=p.timestamp,
            ended_at=self.last.timestamp,
            forward_packets=self.forward,
            backward_packets=self.backward,
            forward_bytes=self.forward_bytes,
            backward_bytes=self.backward_bytes,
            frame_length_min=self.minimum,
            frame_length_max=self.maximum,
            frame_length_mean=self.total / len(self.ids),
            tcp_flag_counts=tuple(sorted(self.flags.items())),
            duration_seconds=(self.last.timestamp - p.timestamp).total_seconds(),
            close_reason=reason,
            source_event_ids=tuple(self.ids),
        )


class FlowTable:
    def __init__(self, config: CaptureConfig):
        self.config = config
        self.flows: dict[tuple, Flow] = {}

    @staticmethod
    def key(packet: PacketObservation):
        endpoints = tuple(
            sorted(
                (
                    (str(packet.source_address), packet.source_port),
                    (str(packet.destination_address), packet.destination_port),
                )
            )
        )
        return packet.interface_id, packet.transport, endpoints

    def expire(self, now: datetime, reason: str | None = None) -> list[FlowSummary]:
        result = []
        for key, flow in list(self.flows.items()):
            elapsed = (now - flow.first.timestamp).total_seconds()
            idle = (now - flow.last.timestamp).total_seconds()
            why = reason or (
                "ACTIVE_TIMEOUT"
                if elapsed >= self.config.active_seconds
                else "IDLE_TIMEOUT"
                if idle >= self.config.idle_seconds
                else None
            )
            if why:
                result.append(flow.summary(why))
                del self.flows[key]
        return result

    def add(self, packet: PacketObservation, event_id: str) -> list[FlowSummary]:
        expired = self.expire(packet.timestamp)
        key = self.key(packet)
        if key not in self.flows:
            if len(self.flows) >= self.config.max_flows:
                raise ValueError("FLOW_CAPACITY_BACKPRESSURE")
            self.flows[key] = Flow(packet, packet)
        flow = self.flows[key]
        flow.add(packet, event_id)
        if len(flow.ids) >= 128:
            expired.append(flow.summary("PACKET_LIMIT"))
            del self.flows[key]
        return expired
