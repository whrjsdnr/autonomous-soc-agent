"""Strict bounded streaming protocol shared by manual Native and no-capture PCAP tests."""

import json
from decimal import Decimal

from pydantic import Field

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import Window
from soc_agent.security_ai.research.models import Frozen

SUMMARY_FIELDS = {
    "ts",
    "uid",
    "id",
    "proto",
    "duration",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "missed_bytes",
    "conn_state",
    "trans_id",
    "qtype",
    "rcode",
    "rtt",
    "TTLs",
    "TC",
}


class Envelope(Frozen):
    sequence: int = Field(gt=0, le=8192, strict=True)
    kind: str = Field(pattern=r"^(ready|packet|network|dns|closed)$")
    data: dict


def decode(line: bytes) -> Envelope:
    if len(line) > 16384 or not line.endswith(b"\n"):
        raise ValueError("ZEEK_STREAM_RECORD_BOUND")
    return Envelope.model_validate(json.loads(line, parse_float=Decimal))


class Stream:
    def __init__(self, source: Source):
        self.source = source
        self.sequence = self.packet_count = self.peak = 0
        self.ready = self.closed = False
        self.active = {}
        self.finalized = []
        self.counters = None
        self.previous_ns = None
        self.out_of_order = 0

    def accept(self, envelope: Envelope):
        e = envelope
        if self.closed or e.sequence != self.sequence + 1:
            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
        if e.kind == "ready":
            if self.ready or self.sequence or e.data:
                raise ValueError("ZEEK_STREAM_READY_INVALID")
            self.ready = True
        elif not self.ready:
            raise ValueError("ZEEK_STREAM_READY_MISSING")
        elif e.kind == "packet":
            p = Packet.model_validate(e.data)
            if p.sequence != self.packet_count + 1 or p.frame_length != p.captured_length:
                raise ValueError("ZEEK_STREAM_PACKET_INTEGRITY")
            if self.previous_ns is not None and p.ns < self.previous_ns:
                self.out_of_order += 1  # Different keys are independent; never reorder/clamp.
            self.previous_ns = p.ns
            old = self.active.get(p.key)
            if old:
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
                    self.finalized.append(old.finish(reason, str(self.source.session_id)))
                    del self.active[p.key]
            if p.key not in self.active:
                if len(self.active) >= 128:
                    raise ValueError("ZEEK_FLOW_STATE_BUDGET")
                self.active[p.key] = Window()
            self.active[p.key].add(p)
            if len(self.active[p.key].packets) == 128:
                self.finalized.append(
                    self.active.pop(p.key).finish("PACKET_LIMIT", str(self.source.session_id))
                )
            self.packet_count += 1
            self.peak = max(self.peak, sum(len(w.packets) for w in self.active.values()))
            if self.peak > 4096 or len(self.finalized) > 1024:
                raise ValueError("ZEEK_FLOW_METADATA_BUDGET")
        elif e.kind in {"network", "dns"}:
            row = dict(e.data)
            if not set(row) <= SUMMARY_FIELDS:
                raise ValueError("ZEEK_STREAM_PRIVACY_REJECTED")
            identity = row.pop("id", None)
            if not isinstance(identity, dict) or set(identity) != {
                "orig_h",
                "orig_p",
                "resp_h",
                "resp_p",
            }:
                raise ValueError("ZEEK_STREAM_ENDPOINT_IDENTITY")
            row.update({"id." + key: value for key, value in identity.items()})
            # Decimal text preserves event time, unlike float round trips.
            stamp = row.pop("ts")
            if isinstance(stamp, bool) or not isinstance(stamp, (int, Decimal)):
                raise ValueError("ZEEK_STREAM_TIMESTAMP_INVALID")
            text = json.dumps(row, default=float)
            raw = (text[:-1] + ',"ts":' + str(stamp) + "}\n").encode()
            event = parse_line(raw, e.kind, self.source)
            self.sequence = e.sequence
            return event
        elif e.kind == "closed":
            if not set(e.data) <= {"pkts_recvd", "pkts_dropped", "pkts_link", "bytes_recvd"}:
                raise ValueError("ZEEK_STREAM_COUNTER_SCHEMA")
            if any(type(v) is not int or v < 0 for v in e.data.values()):
                raise ValueError("ZEEK_STREAM_COUNTER_SCHEMA")
            self.counters = e.data
            self.closed = True
            self.finalized.extend(
                w.finish("SHUTDOWN", str(self.source.session_id)) for w in self.active.values()
            )
            self.active.clear()
            if e.data.get("pkts_dropped", 0):
                raise ValueError("ZEEK_CAPTURE_DROPS_DETECTED")
            # Zero alone is NEVER capture attestation. Native remains UNVERIFIED.
        self.sequence = e.sequence
        return None
