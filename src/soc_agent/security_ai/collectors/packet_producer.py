"""Bounded first-seen/event-time windows; all 14 candidate features, no imputation."""

import math
import struct
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import IPvAnyAddress

from soc_agent.security_ai.collectors.packet_input import SCOPE, Packet
from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.research.models import digest

VERSION = "zeek-packet-network14:v1"


class FeaturePacket(Protocol):
    """Only event-time arithmetic and in-memory metadata; no assumed UTC clock."""

    sequence: int
    ns: int
    key: tuple
    source: IPvAnyAddress
    source_port: int
    ip_length: int
    tcp_flags: int

    def model_dump(self, *, mode: str) -> dict: ...


@dataclass
class Window:
    compact: bool = False
    count: int = 0
    packets: list[FeaturePacket] = field(default_factory=list)
    total: int = 0
    squares: int = 0
    forward: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    minimum: int = 65535
    maximum: int = 0
    syn: int = 0
    fin: int = 0
    rst: int = 0
    iat_sum: int = 0
    iat_max: int = 0

    def add(self, p: FeaturePacket):
        if self.packets:
            delta = p.ns - self.packets[-1].ns
            if delta < 0:
                raise ValueError("ZEEK_FLOW_TIMESTAMP_REGRESSION")
            self.iat_sum += delta
            self.iat_max = max(self.iat_max, delta)
        first = self.packets[0] if self.packets else p
        forward = (p.source, p.source_port) == (first.source, first.source_port)
        self.forward += int(forward)
        self.forward_bytes += p.ip_length if forward else 0
        self.backward_bytes += p.ip_length if not forward else 0
        self.total += p.ip_length
        self.squares += p.ip_length**2
        self.minimum = min(self.minimum, p.ip_length)
        self.maximum = max(self.maximum, p.ip_length)
        self.syn += bool(p.tcp_flags & 2)
        self.fin += bool(p.tcp_flags & 1)
        self.rst += bool(p.tcp_flags & 4)
        self.count += 1
        if self.compact and self.packets:
            self.packets = [self.packets[0], p]
        else:
            self.packets.append(p)

    def finish(self, reason: str, session: str) -> dict:
        n = self.count
        values = (
            (self.packets[-1].ns - self.packets[0].ns) / 1e9,
            self.forward,
            n - self.forward,
            self.forward_bytes,
            self.backward_bytes,
            self.minimum,
            self.maximum,
            self.total / n,
            math.sqrt((self.squares * n - self.total**2) / (n * n)),
            self.syn,
            self.fin,
            self.rst,
            self.iat_sum / (n - 1) / 1e9 if n > 1 else 0.0,
            self.iat_max / 1e9,
        )
        values = tuple(struct.unpack("!f", struct.pack("!f", v))[0] for v in values)
        return dict(
            flow_id=digest(
                dict(key=self.packets[0].key, session=session, first=self.packets[0].sequence)
            ),
            close_reason=reason,
            packet_count=n,
            eligible=reason in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"},
            packets=[p.model_dump(mode="json") for p in self.packets],
            values=list(values),
            values_digest=digest(values),
            feature_names=[n for n, _, _ in NETWORK14],
        )


class FlowAssembly:
    """One bounded event-time assembler shared by offline and streaming callers.

    Same-key timeouts preserve v1 windows. FIN/RST are feature flags, never new
    completion authority. The caller must explicitly finish an exhausted source.
    """

    def __init__(self, session: str, *, event_watermark: bool = False, compact: bool = False):
        self.session = session
        self.event_watermark = event_watermark
        self.compact = compact
        self.watermark: int | None = None
        self.active: dict[tuple, Window] = {}
        self.finalized: list[dict] = []
        self.count = self.peak = 0
        self.closed = False

    def add(self, p: FeaturePacket) -> FeaturePacket:
        if self.closed or p.sequence != self.count + 1:
            raise ValueError("ZEEK_FLOW_SEQUENCE_INTEGRITY")
        if self.event_watermark:
            if self.watermark is not None and p.ns < self.watermark:
                raise ValueError("FLOW_WATERMARK_CLOCK_REGRESSION")
            # Observed event time only. No processing/wall-clock idle completion.
            self.watermark = p.ns
            for key, old in tuple(self.active.items()):
                reason = (
                    "ACTIVE_TIMEOUT"
                    if p.ns - old.packets[0].ns >= 120_000_000_000
                    else "IDLE_TIMEOUT"
                    if p.ns - old.packets[-1].ns >= 30_000_000_000
                    else None
                )
                if reason:
                    self.finalized.append(old.finish(reason, self.session))
                    del self.active[key]
        key = p.key
        if key in self.active:
            old = self.active[key]
            delta = p.ns - old.packets[-1].ns
            if delta < 0:
                raise ValueError("ZEEK_FLOW_TIMESTAMP_REGRESSION")
            reason = (
                "ACTIVE_TIMEOUT"
                if p.ns - old.packets[0].ns >= 120_000_000_000
                else "IDLE_TIMEOUT"
                if delta >= 30_000_000_000
                else None
            )
            if reason:
                self.finalized.append(old.finish(reason, self.session))
                del self.active[key]
        if key not in self.active:
            if len(self.active) >= 128:
                raise ValueError("ZEEK_FLOW_STATE_BUDGET")
            self.active[key] = Window(compact=self.compact)
        first = self.active[key].packets[0] if self.active[key].packets else p
        self.active[key].add(p)
        self.count += 1
        self.peak = max(self.peak, sum(len(w.packets) for w in self.active.values()))
        if self.peak > 4096 or self.count > 4096:
            raise ValueError("ZEEK_FLOW_METADATA_BUDGET")
        if not self.compact and len(self.active[key].packets) == 128:
            self.finalized.append(self.active.pop(key).finish("PACKET_LIMIT", self.session))
        if len(self.finalized) > 1024:
            raise ValueError("ZEEK_FLOW_COMPLETION_BUDGET")
        return first

    def finish(self, reason: str = "SHUTDOWN") -> None:
        if self.closed:
            raise ValueError("ZEEK_FLOW_ALREADY_FINALIZED")
        if reason not in {
            "SHUTDOWN",
            "PACKET_LIMIT",
            "RESTART_GAP",
            "CAPTURE_STOP",
            "QUEUE_OVERFLOW",
            "CLOCK_INVALID",
            "INCOMPLETE",
            "NORMAL_END",
        }:
            raise ValueError("ZEEK_FLOW_UNSUPPORTED_FINALIZATION")
        self.finalized.extend(w.finish(reason, self.session) for w in self.active.values())
        self.active.clear()
        self.closed = True
        if len(self.finalized) > 1024:
            raise ValueError("ZEEK_FLOW_COMPLETION_BUDGET")


def aggregate(packets: tuple[Packet, ...], session: str) -> dict:
    if not 1 <= len(packets) <= 4096:
        raise ValueError("ZEEK_FLOW_PACKET_BUDGET")
    assembly = FlowAssembly(session)
    for p in packets:
        assembly.add(p)
    assembly.finish()
    return dict(
        producer=VERSION,
        scope=SCOPE,
        flow_policy="SAME_KEY_EVENT_TIME_ONLY",
        packet_count=len(packets),
        peak_packet_references=assembly.peak,
        active_final=0,
        flows=assembly.finalized,
        eligible=sum(f["eligible"] for f in assembly.finalized),
        rejected=sum(not f["eligible"] for f in assembly.finalized),
        network14_parity="PENDING_INDEPENDENT_ML_REFERENCE",
        dns9_parity="BLOCKED",
    )
