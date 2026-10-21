"""Strict bounded streaming protocol shared by manual Native and no-capture PCAP tests."""

import json
from decimal import Decimal

from pydantic import Field

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.finalization import Closed, CounterSnapshot
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.packet_metadata import (
    EVENT_TYPES,
    ObservationFlows,
    UnsupportedPacket,
    packet_metadata,
)
from soc_agent.security_ai.collectors.preprocessing import DNSPreprocessing, normalize
from soc_agent.security_ai.research.models import Frozen, digest

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
    kind: str = Field(pattern=r"^(ready|packet|unsupported|network|dns|counter|closed)$")
    data: dict

    @property
    def event_type(self) -> str:
        return EVENT_TYPES[self.kind]


def decode(line: bytes) -> Envelope:
    if len(line) > 16384 or not line.endswith(b"\n"):
        raise ValueError("ZEEK_STREAM_RECORD_BOUND")
    return Envelope.model_validate(json.loads(line, parse_float=Decimal))


class Stream:
    def __init__(self, source: Source):
        self.source = source
        self.sequence = self.packet_count = self.peak = 0
        self.ready = self.closed = False
        self.flows = ObservationFlows(str(source.session_id))
        self.active = self.flows.active
        self.finalized = self.flows.finalized
        self.normalization_digest = digest(source.model_dump(mode="json"))
        self.dns_preprocessing = DNSPreprocessing(source)
        self.counters = None
        self.previous_ns = None
        self.out_of_order = 0
        self.network_count = self.dns_count = 0
        self.port53_metadata_packets = 0
        self.closed_detail = None
        self.dns_stages = None
        self.dns_adapter_rejected = 0
        self.observation_count = self.unsupported_count = 0
        self.total_received = self.invalid = self.duplicate = self.sequence_gap = 0
        self.counter_snapshot: CounterSnapshot | None = None

    def diagnostics(self) -> dict:
        return dict(
            total_received=self.total_received,
            packet_observations=self.observation_count,
            supported_packet=self.packet_count,
            unsupported_packet=self.unsupported_count,
            network_event=self.network_count,
            dns_event=self.dns_count,
            invalid_record=self.invalid,
            duplicate=self.duplicate,
            sequence_gap=self.sequence_gap,
            closed=self.closed,
            counter_snapshot=self.counter_snapshot.model_dump() if self.counter_snapshot else None,
        )

    def accept(self, envelope: Envelope):
        self.total_received += 1
        self.duplicate += int(envelope.sequence <= self.sequence)
        self.sequence_gap += int(envelope.sequence > self.sequence + 1)
        try:
            return self._accept(envelope)
        except (ValueError, TypeError):
            self.invalid += 1
            raise

    def _accept(self, envelope: Envelope):
        e = envelope
        if self.closed or e.sequence != self.sequence + 1:
            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
        if e.kind == "ready":
            if self.ready or self.sequence or e.data:
                raise ValueError("ZEEK_STREAM_READY_INVALID")
            self.ready = True
        elif not self.ready:
            raise ValueError("ZEEK_STREAM_READY_MISSING")
        elif self.counter_snapshot is not None and e.kind != "closed":
            raise ValueError("ZEEK_STREAM_POST_COUNTER_RECORD")
        elif e.kind == "unsupported":
            metadata = UnsupportedPacket.model_validate(e.data)
            if metadata.sequence != self.observation_count + 1:
                raise ValueError("ZEEK_STREAM_PACKET_INTEGRITY")
            self.flows.exclude(metadata)
            self.unsupported_count += 1
            self.observation_count += 1
            self.normalization_digest = digest(
                dict(
                    previous=self.normalization_digest,
                    excluded_unsupported=e.data,
                    event_sequence=e.sequence,
                )
            )
        elif e.kind == "packet":
            p = packet_metadata(e.kind, e.data)
            if p.sequence != self.observation_count + 1 or p.frame_length != p.captured_length:
                raise ValueError("ZEEK_STREAM_PACKET_INTEGRITY")
            if self.previous_ns is not None and p.ns < self.previous_ns:
                self.out_of_order += 1  # Different keys are independent; never reorder/clamp.
            self.previous_ns = p.ns
            first = self.flows.add(p)
            normalized = normalize(p, self.source, e.sequence, first)
            self.normalization_digest = digest(
                dict(previous=self.normalization_digest, packet=normalized.model_dump(mode="json"))
            )
            self.port53_metadata_packets += int(53 in (p.source_port, p.destination_port))
            self.packet_count += 1
            self.observation_count += 1
            self.peak = max(self.peak, sum(len(w.packets) for w in self.active.values()))
            if self.peak > 4096 or len(self.finalized) > 1024:
                raise ValueError("ZEEK_FLOW_METADATA_BUDGET")
        elif e.kind in {"network", "dns"}:
            if e.kind == "dns":
                self.dns_adapter_rejected += 1
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
            stamp = row.pop("ts", None)
            if isinstance(stamp, bool) or not isinstance(stamp, (int, Decimal)):
                raise ValueError("ZEEK_STREAM_TIMESTAMP_INVALID")
            text = json.dumps(row, default=float)
            raw = (text[:-1] + ',"ts":' + str(stamp) + "}\n").encode()
            event = parse_line(raw, e.kind, self.source)
            if e.kind == "network":
                self.network_count += 1
            else:
                self.dns_preprocessing.add(event)
                self.dns_adapter_rejected -= 1
                self.dns_count += 1
            self.sequence = e.sequence
            return event
        elif e.kind == "counter":
            counter = CounterSnapshot.model_validate(e.data)
            counter.verify(
                self.observation_count, self.unsupported_count, self.network_count, self.dns_count
            )
            self.counter_snapshot = counter
        elif e.kind == "closed":
            counters = e.data
            if "stop_reason" in e.data:
                from soc_agent.security_ai.collectors.dns_visibility import closed_data

                body, self.dns_stages = closed_data(e.data)
                proof = Closed.model_validate(body)
                proof.verify(
                    sequence=e.sequence,
                    packets=self.observation_count,
                    unsupported=self.unsupported_count,
                    counter_messages=int(self.counter_snapshot is not None),
                    network=self.network_count,
                    dns=self.dns_count,
                )
                if self.counter_snapshot:
                    self.counter_snapshot.verify_closed(proof)
                self.closed_detail = proof
                counters = {
                    key: getattr(proof, key)
                    for key in ("pkts_recvd", "pkts_dropped", "pkts_link", "bytes_recvd")
                }
            elif not set(e.data) <= {"pkts_recvd", "pkts_dropped", "pkts_link", "bytes_recvd"}:
                raise ValueError("ZEEK_STREAM_COUNTER_SCHEMA")
            if "stop_reason" not in e.data and self.unsupported_count:
                raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
            if any(type(v) is not int or v < 0 for v in counters.values()):
                raise ValueError("ZEEK_STREAM_COUNTER_SCHEMA")
            self.counters = counters
            self.closed = True
            self.flows.finish(
                "PACKET_LIMIT"
                if self.closed_detail and self.closed_detail.stop_reason == "PACKET_LIMIT_REACHED"
                else "SHUTDOWN"
            )
            if counters.get("pkts_dropped", 0):
                raise ValueError("ZEEK_CAPTURE_DROPS_DETECTED")
            # Zero alone is NEVER capture attestation. Native remains UNVERIFIED.
        self.sequence = e.sequence
        return None
