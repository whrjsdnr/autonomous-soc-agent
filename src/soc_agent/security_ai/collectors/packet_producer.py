"""Bounded first-seen/event-time windows; all 14 candidate features, no imputation."""

import math
import struct
from dataclasses import dataclass, field

from soc_agent.security_ai.collectors.packet_input import SCOPE, Packet
from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.research.models import digest

VERSION = "zeek-packet-network14:v1"


@dataclass
class Window:
    packets: list[Packet] = field(default_factory=list)
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

    def add(self, p: Packet):
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
        self.packets.append(p)

    def finish(self, reason: str, session: str) -> dict:
        n = len(self.packets)
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
            eligible=reason in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"},
            packets=[p.model_dump(mode="json") for p in self.packets],
            values=list(values),
            values_digest=digest(values),
            feature_names=[n for n, _, _ in NETWORK14],
        )


def aggregate(packets: tuple[Packet, ...], session: str) -> dict:
    if not 1 <= len(packets) <= 4096:
        raise ValueError("ZEEK_FLOW_PACKET_BUDGET")
    active, finished = {}, []
    peak = 0
    for i, p in enumerate(packets, 1):
        if p.sequence != i:
            raise ValueError("ZEEK_FLOW_SEQUENCE_INTEGRITY")
        key = p.key
        if key in active:
            old = active[key]
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
                finished.append(old.finish(reason, session))
                del active[key]
        if key not in active:
            if len(active) >= 128:
                raise ValueError("ZEEK_FLOW_STATE_BUDGET")
            active[key] = Window()
        active[key].add(p)
        peak = max(peak, sum(len(w.packets) for w in active.values()))
        if peak > 4096:
            raise ValueError("ZEEK_FLOW_METADATA_BUDGET")
        if len(active[key].packets) == 128:
            finished.append(active.pop(key).finish("PACKET_LIMIT", session))
        if len(finished) > 1024:
            raise ValueError("ZEEK_FLOW_COMPLETION_BUDGET")
    finished.extend(w.finish("SHUTDOWN", session) for w in active.values())
    if len(finished) > 1024:
        raise ValueError("ZEEK_FLOW_COMPLETION_BUDGET")
    return dict(
        producer=VERSION,
        scope=SCOPE,
        flow_policy="SAME_KEY_EVENT_TIME_ONLY",
        packet_count=len(packets),
        peak_packet_references=peak,
        active_final=0,
        flows=finished,
        eligible=sum(f["eligible"] for f in finished),
        rejected=sum(not f["eligible"] for f in finished),
        network14_parity="PENDING_INDEPENDENT_ML_REFERENCE",
        dns9_parity="BLOCKED",
    )
