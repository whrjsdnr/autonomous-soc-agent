"""Metadata normalization and quality projections; never capture or model authority."""

from collections import Counter
from typing import Literal

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.collectors.integrity import (
    eligibility,
    offline_eligibility,
    validate_flow,
)
from soc_agent.security_ai.collectors.models import Event, Source
from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import VERSION
from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.research.models import Frozen, digest


class NormalizedPacket(Frozen):
    contract: Literal["soc-zeek-normalized-packet:v1"] = "soc-zeek-normalized-packet:v1"
    session_id: str
    source_digest: Hash
    origin: str
    event_sequence: int = Field(ge=1, le=8192, strict=True)
    packet: Packet
    flow_key: Hash
    direction: Literal["FIRST_SEEN_FORWARD", "FIRST_SEEN_BACKWARD"]
    timestamp_precision: Literal["DECLARED_MICROSECONDS_NATIVE_ACCURACY_UNVERIFIED"] = (
        "DECLARED_MICROSECONDS_NATIVE_ACCURACY_UNVERIFIED"
    )
    capture_integrity: str
    parser_support: Literal["ETHERNET_IP_TCP_UDP_METADATA_ONLY"] = (
        "ETHERNET_IP_TCP_UDP_METADATA_ONLY"
    )


def normalize(
    packet: Packet, source: Source, event_sequence: int, first: Packet
) -> NormalizedPacket:
    ipv6 = packet.source.version == 6
    minimum = (40 if ipv6 else 20) + (20 if packet.kind == "tcp" else 8)
    if (
        packet.source.version != packet.destination.version
        or packet.frame_length != packet.captured_length
        or packet.ip_length < minimum
        or packet.ip_length + 14 > packet.frame_length
        or packet.kind == "udp"
        and packet.tcp_flags != 0
        or packet.key != first.key
        or (packet.source, packet.source_port) == (packet.destination, packet.destination_port)
    ):
        raise ValueError("ZEEK_NORMALIZATION_UNSUPPORTED_PACKET")
    return NormalizedPacket(
        session_id=str(source.session_id),
        source_digest=source.source_digest,
        origin=source.origin,
        event_sequence=event_sequence,
        packet=packet,
        flow_key=digest(dict(session=str(source.session_id), key=packet.key)),
        direction="FIRST_SEEN_FORWARD"
        if (packet.source, packet.source_port) == (first.source, first.source_port)
        else "FIRST_SEEN_BACKWARD",
        capture_integrity=source.capture_integrity,
    )


class DNSPreprocessing:
    """Zeek transaction summaries, not reconstructed raw queries or lexical DNS9."""

    def __init__(self, source: Source):
        self.source = source
        self.seen: dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self.last_ns: int | None = None

    def add(self, event: Event) -> None:
        if event.source != self.source or event.kind != "dns":
            raise ValueError("ZEEK_DNS_PREPROCESSING_SOURCE_MISMATCH")
        value = digest(event.model_dump(mode="json"))
        if event.event_id in self.seen:
            if self.seen[event.event_id] != value:
                raise ValueError("ZEEK_DNS_DUPLICATE_CONFLICT")
            self.counts["duplicate_records"] += 1
            return
        if len(self.seen) >= 4096:
            raise ValueError("ZEEK_DNS_PREPROCESSING_BUDGET")
        if event.protocol not in {"tcp", "udp"}:
            raise ValueError("ZEEK_DNS_PREPROCESSING_UNSUPPORTED_TRANSPORT")
        self.seen[event.event_id] = value
        self.counts[event.diagnostic] += 1
        self.counts[event.protocol] += 1
        self.counts["missing_transaction_id"] += event.transaction_id is None
        self.counts["missing_query_type"] += event.query_type is None
        self.counts["missing_ttl_metadata"] += event.ttl_seconds is None
        if self.last_ns is not None and event.event_ns < self.last_ns:
            # dns.log timestamps denote transaction starts; log completion can reorder them.
            self.counts["out_of_order_transaction_starts"] += 1
        self.last_ns = event.event_ns

    def snapshot(self) -> dict:
        return dict(
            records=len(self.seen),
            counters=dict(self.counts),
            timestamp_scope="TRANSACTION_START_NOT_QUERY_RESPONSE_PACKET_ORDER",
            query_response_matching="ZEEK_TRANSACTION_METADATA_NOT_INDEPENDENT_PACKET_MATCH",
            query_packets=None,
            response_packets=None,
            dns9="BLOCKED",
            fqdn_retained=False,
        )


def progress(stream) -> dict:
    if stream is None or not stream.ready:
        return dict(state="NOT_OBSERVED", normalized_packets=None, active_flows=None)
    return dict(
        state="FINALIZED" if stream.closed else "STREAMING_METADATA",
        normalized_packets=stream.packet_count,
        normalization_digest=stream.normalization_digest,
        active_flows=len(stream.active),
        finalized_flows=len(stream.finalized),
        finalization_reasons=dict(Counter(f["close_reason"] for f in stream.finalized)),
        dns=stream.dns_preprocessing.snapshot(),
        capture_integrity=stream.source.capture_integrity,
        timestamp_precision="DECLARED_USEC_NATIVE_PARITY_UNVERIFIED",
        flow_policy="SAME_KEY_EVENT_TIME_30S_IDLE_120S_ACTIVE_NO_WALLCLOCK_EXPIRY",
        tcp_fin_policy="FEATURE_ONLY_NO_NEW_FINALIZATION_AUTHORITY",
        tcp_rst_policy="FEATURE_ONLY_NO_NEW_FINALIZATION_AUTHORITY",
        resource_limits=dict(active_flows=128, packets_per_flow=128, packets=4096, flows=1024),
        native_ai="BLOCKED",
    )


def final_summary(collector, stream) -> dict:
    from soc_agent.security_ai.collectors.integrity_service import report_from, summary

    c = collector
    session = report_from(summary(c.plan, stream, c.result))
    offline = (
        c.fixture
        and c.store.source.origin == "ZEEK_OFFLINE_PCAP"
        and c.store.source.capture_integrity == "OFFLINE_FILE_DIGEST_VERIFIED"
    )
    records = c.producer.snapshot()["research"]["records"] if c.producer and offline else []
    receipts: dict[str, set[str]] = {}
    feature_digests: dict[str, str] = {}
    for row in records:
        if row.get("status") == "COMPLETE" and row.get("receipt"):
            receipt = row["receipt"]
            receipts.setdefault(receipt["flow_id"], set()).add(receipt["profile"])
            feature_digests[receipt["flow_id"]] = receipt["feature_digest"]
    termination = c.result.get("termination_reason", "UNKNOWN")
    context = {
        "PACKET_LIMIT_REACHED": "PACKET_LIMIT",
        "EVENT_LIMIT_REACHED": "EVENT_LIMIT",
        "OUTPUT_LIMIT_REACHED": "OUTPUT_LIMIT",
    }.get(termination, "COLLECTOR_STOP")
    reasons: Counter[str] = Counter()
    checked = []
    complete = 0
    for flow in stream.finalized:
        validation = validate_flow(flow, c.store.source.session_id)
        complete += validation.completeness == "VERIFIED"
        profiles = receipts.get(flow["flow_id"], set())
        verified = bool(profiles)
        decision = (
            offline_eligibility(
                validation,
                parity="VERIFIED" if verified else "UNVERIFIED",
                artifact="VERIFIED" if profiles == {"quality", "edge"} else "NOT_OBSERVED",
            )
            if offline
            else eligibility(session, validation, parity="UNVERIFIED", artifact="NOT_OBSERVED")
        )
        reasons[decision.decision] += 1
        checked.append(
            dict(
                flow_id=flow["flow_id"],
                values_digest=validation.values_digest,
                feature_digest=feature_digests.get(flow["flow_id"]),
                completeness=validation.completeness,
                feature_integrity=validation.feature_integrity,
                close_reason=flow["close_reason"],
                finalization_context=context
                if flow["close_reason"] == "SHUTDOWN"
                else flow["close_reason"],
                artifact_eligibility={
                    p: "VERIFIED_RECEIPT" if p in profiles else "NOT_OBSERVED"
                    for p in ("quality", "edge")
                },
                decision=decision.model_dump(mode="json"),
            )
        )
    return dict(
        contract="soc-zeek-preprocessing-summary:v1",
        session_id=str(c.plan.session_id),
        source_digest=c.store.source.source_digest,
        input_origin=c.store.source.origin,
        plan_digest=c.plan.identity,
        stream_digest=c.result["stream_sha256"],
        producer_version=VERSION,
        reference_producer_version="1.1.0",
        feature_names=[n for n, _, _ in NETWORK14],
        dtype="float32",
        missing_value_policy="REJECT_NO_IMPUTATION",
        progress=progress(stream),
        capture_integrity=session.capture,
        completed_flows=complete,
        incomplete_flows=len(checked) - complete,
        feature_decisions=dict(reasons),
        flow_decisions_digest=digest(checked),
        flow_quality_tail=checked[-4:],
        termination_reason=termination,
        collector_stop_context=context,
        closed_reason=stream.closed_detail.stop_reason if stream.closed_detail else "UNKNOWN",
        flow_boundary_policy="UNCHANGED_TIMEOUT_WINDOWS_FIN_RST_ARE_FEATURES",
        fixed_sliding_window="EXPERIMENTAL_NOT_MODEL_INPUT",
        raw_payload_retained=False,
        native_ai="BLOCKED",
        dns9="BLOCKED",
        operational_gate="BLOCKED",
    )
