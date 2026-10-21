"""Evidence classifications, never a replacement for source admission or model policy.

A numeric Zeek NetStats record has no query-success signal. Neither a successful
process nor locally reproducible feature arithmetic makes Native capture verified.
"""

import math
import struct
from typing import Literal
from uuid import UUID

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer

from soc_agent.review.models import Hash
from soc_agent.security_ai.collectors.finalization import Closed
from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import Window
from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.research.models import Frozen, digest

Status = Literal["VERIFIED", "DEGRADED", "UNVERIFIED", "FAILED", "NOT_OBSERVED"]
Block = Literal[
    "ELIGIBLE",
    "BLOCKED_CAPTURE_INTEGRITY",
    "BLOCKED_FEATURE_PARITY",
    "BLOCKED_ARTIFACT",
    "BLOCKED_FLOW_INCOMPLETE",
    "BLOCKED_UNSUPPORTED_INPUT",
    "BLOCKED_POLICY",
    "UNKNOWN",
]


class CounterSample(Frozen):
    session_id: UUID
    plan_digest: Hash
    handle_id: Hash
    sequence: int = Field(ge=1, strict=True)
    stage: Literal["READY", "INTERVAL", "CLOSED"]
    query_ok: bool | None = Field(default=None, strict=True)
    received: int | None = Field(default=None, ge=0, strict=True)
    dropped: int | None = Field(default=None, ge=0, strict=True)


class CounterReport(Frozen):
    status: Status
    provenance: Literal["ZEEK_GET_NET_STATS_9_0_0", "SAME_HANDLE_FIXTURE", "NOT_OBSERVED"]
    reason: str
    reported_received: int | None = Field(default=None, ge=0, strict=True)
    reported_drops: int | None = Field(default=None, ge=0, strict=True)
    reported_link: int | None = Field(default=None, ge=0, strict=True)
    kernel_drops_verified: int | None = Field(default=None, ge=0, strict=True)
    query_status: Literal["VERIFIED", "FAILED", "UNKNOWN"] = "UNKNOWN"


def counter_fixture(
    samples: tuple[CounterSample, ...],
    *,
    session: UUID,
    plan: str,
    handle: str,
    semantics: Literal["CUMULATIVE", "RESET_ON_READ"],
) -> CounterReport:
    """Validate proposed same-handle evidence with fixtures. Not a Native attestation API."""

    def report(status, reason, **kwargs):
        return CounterReport(
            status=status, provenance="SAME_HANDLE_FIXTURE", reason=reason, **kwargs
        )

    if not 2 <= len(samples) <= 602:
        return report("UNVERIFIED", "MISSING_COUNTER_WINDOW")
    received = dropped = 0
    previous_received = previous_dropped = 0
    for i, sample in enumerate(samples, 1):
        if (
            sample.sequence != i
            or sample.session_id != session
            or sample.plan_digest != plan
            or sample.handle_id != handle
            or sample.stage
            != ("READY" if i == 1 else "CLOSED" if i == len(samples) else "INTERVAL")
        ):
            return report("FAILED", "COUNTER_SEQUENCE_OR_SOURCE_MISMATCH")
        if sample.query_ok is False:
            return report("FAILED", "COUNTER_QUERY_FAILED", query_status="FAILED")
        if sample.query_ok is not True or sample.received is None or sample.dropped is None:
            return report("UNVERIFIED", "COUNTER_QUERY_UNKNOWN")
        if semantics == "CUMULATIVE":
            if sample.received < previous_received or sample.dropped < previous_dropped:
                return report("FAILED", "COUNTER_RESET_OR_REGRESSION")
            received, dropped = sample.received, sample.dropped
            previous_received, previous_dropped = received, dropped
        elif semantics == "RESET_ON_READ":
            received += sample.received
            dropped += sample.dropped
        else:
            return report("FAILED", "UNKNOWN_COUNTER_SEMANTICS")
    return report(
        "FAILED" if dropped else "VERIFIED",
        "DROPS_DETECTED" if dropped else "WINDOW_VERIFIED",
        reported_received=received,
        reported_drops=dropped,
        kernel_drops_verified=dropped,
        query_status="VERIFIED",
    )


def zeek_counter(closed: Closed | None) -> CounterReport:
    if closed is None:
        return CounterReport(
            status="NOT_OBSERVED", provenance="NOT_OBSERVED", reason="MISSING_CLOSED_COUNTER"
        )
    return CounterReport(
        status="FAILED" if closed.pkts_dropped else "UNVERIFIED",
        provenance="ZEEK_GET_NET_STATS_9_0_0",
        reason="REPORTED_DROPS" if closed.pkts_dropped else "QUERY_SUCCESS_AND_WINDOW_NOT_ATTESTED",
        reported_received=closed.pkts_recvd,
        reported_drops=closed.pkts_dropped,
        reported_link=closed.pkts_link,
    )


class FlowReport(Frozen):
    feature_integrity: Status
    completeness: Status
    reason: str
    values_digest: Hash | None = None
    flow_id: Hash | None = None
    packet_count: int | None = Field(default=None, ge=0, strict=True)


def validate_flow(flow: dict, session: UUID) -> FlowReport:
    """Recompute stored metadata arithmetic; independent ML/packet parity is separate."""
    try:
        packets = tuple(Packet.model_validate(p) for p in flow["packets"])
        if not 1 <= len(packets) <= 128:
            raise ValueError("packet bound")
        w = Window()
        previous = 0
        for p in packets:
            if (
                p.key != packets[0].key
                or p.sequence <= previous
                or p.frame_length != p.captured_length
                or (p.kind == "udp" and p.tcp_flags)
                or (p.source, p.source_port) == (p.destination, p.destination_port)
            ):
                raise ValueError("unsupported metadata or direction")
            if w.packets and (
                p.ns - packets[0].ns >= 120_000_000_000 or p.ns - w.packets[-1].ns >= 30_000_000_000
            ):
                raise ValueError("timeout boundary")
            w.add(p)
            previous = p.sequence
        reason = flow["close_reason"]
        if reason not in {
            "IDLE_TIMEOUT",
            "ACTIVE_TIMEOUT",
            "PACKET_LIMIT",
            "SHUTDOWN",
            "RESTART_GAP",
        }:
            raise ValueError("unknown boundary")
        expected = w.finish(reason, str(session))
        values = flow["values"]
        if (
            flow["feature_names"] != [n for n, _, _ in NETWORK14]
            or len(values) != 14
            or any(
                type(v) not in (int, float)
                or not math.isfinite(v)
                or struct.unpack("!f", struct.pack("!f", v))[0] != v
                for v in values
            )
            or values != expected["values"]
            or flow["values_digest"] != digest(tuple(values))
            or flow["flow_id"] != expected["flow_id"]
            or flow["eligible"] is not expected["eligible"]
        ):
            return FlowReport(
                feature_integrity="FAILED",
                completeness="UNVERIFIED",
                reason="FEATURE_OR_FLOW_DIGEST_MISMATCH",
            )
        return FlowReport(
            feature_integrity="VERIFIED",
            completeness="VERIFIED" if expected["eligible"] else "DEGRADED",
            reason=reason,
            values_digest=flow["values_digest"],
            flow_id=flow["flow_id"],
            packet_count=len(packets),
        )
    except (ValueError, KeyError, TypeError, OverflowError):
        return FlowReport(
            feature_integrity="FAILED",
            completeness="UNVERIFIED",
            reason="UNSUPPORTED_OR_INVALID_PACKET_WINDOW",
        )


class SessionReport(Frozen):
    session_id: UUID
    plan_digest: Hash
    stream_digest: Hash | None = None
    process: Status
    stream: Status
    counter: CounterReport
    capture: Status
    flow_completeness: Status
    packet_records: int | None = Field(default=None, ge=0, le=4096, strict=True)
    supported_packet_records: int | None = Field(default=None, ge=0, le=4096, strict=True)
    unsupported_packet_records: int | None = Field(default=None, ge=0, le=4096, strict=True)
    network_events: int | None = Field(default=None, ge=0, le=8192, strict=True)
    dns_events: int | None = Field(default=None, ge=0, le=8192, strict=True)
    gaps: int | None = Field(default=None, ge=0, strict=True)
    network14_parity: Status = "UNVERIFIED"
    port53_metadata_packets: int | None = Field(default=None, ge=0, le=4096, strict=True)
    dns_visibility: str = "UNKNOWN"
    native_policy: Literal["BLOCKED"] = "BLOCKED"

    @model_serializer(mode="wrap")
    def serialize_counts(self, handler: SerializerFunctionWrapHandler) -> dict:
        value = handler(self)
        for name in ("supported_packet_records", "unsupported_packet_records"):
            if value.get(name) is None:
                value.pop(name, None)
        return value


def assess_session(
    session: UUID,
    plan: str,
    result: dict | None,
    *,
    protocol_verified: bool,
    queue_depth: int | None,
    flows: tuple[FlowReport, ...] = (),
    failed: bool = False,
    port53_metadata_packets: int | None = None,
) -> SessionReport:
    result = result or {}
    try:
        closed = (
            Closed.model_validate(result["closed_detail"]) if result.get("closed_detail") else None
        )
    except ValueError:
        closed = None
        failed = True
    if result and result.get("plan_digest") != plan:
        failed = True
    process: Status = (
        "NOT_OBSERVED"
        if not result
        else "VERIFIED"
        if type(result.get("exit_code")) is int
        and result["exit_code"] in {0, 124}
        and result.get("cleanup_verified") is True
        and result.get("container_absent") is True
        else "FAILED"
        if type(result.get("exit_code")) is int
        and result["exit_code"] not in {0, 124}
        or result.get("cleanup_verified") is False
        else "UNVERIFIED"
    )
    stream = (
        "VERIFIED"
        if protocol_verified
        and result.get("protocol_finalized") is True
        and closed
        and queue_depth == 0
        else "UNVERIFIED"
    )
    counter = zeek_counter(closed)
    capture = (
        "FAILED"
        if failed or result.get("error") or process == "FAILED" or counter.status == "FAILED"
        else "UNVERIFIED"
    )
    complete = (
        "DEGRADED"
        if closed
        and (
            closed.stop_reason != "ZEEK_DONE"
            or closed.omitted_events
            or closed.omitted_packet_records
            or closed.unsupported_packet_records
        )
        else (
            "VERIFIED"
            if flows and all(f.completeness == "VERIFIED" for f in flows)
            else "UNVERIFIED"
        )
    )
    return SessionReport(
        session_id=session,
        plan_digest=plan,
        stream_digest=result.get("stream_sha256"),
        process=process,
        stream=stream,
        counter=counter,
        capture=capture,
        flow_completeness=complete,
        packet_records=closed.packet_records if closed else None,
        supported_packet_records=closed.supported_packet_records if closed else None,
        unsupported_packet_records=closed.unsupported_packet_records if closed else None,
        network_events=closed.network_events if closed else None,
        dns_events=closed.dns_events if closed else None,
        # An intact metadata stream does not attest that there were no capture gaps.
        gaps=None,
        port53_metadata_packets=port53_metadata_packets,
        dns_visibility="DNS_EVENT_OBSERVED"
        if closed and closed.dns_events
        else "UNKNOWN_PORT53_METADATA_WITHOUT_DNS_EVENT"
        if port53_metadata_packets
        else "UNKNOWN_NO_DNS_EVENT",
    )


class Eligibility(Frozen):
    decision: Block
    blockers: tuple[Block, ...]
    authority: Literal["DIAGNOSTIC_ONLY_NO_NATIVE_AUTHORIZATION"] = (
        "DIAGNOSTIC_ONLY_NO_NATIVE_AUTHORIZATION"
    )


def eligibility(
    report: SessionReport,
    flow: FlowReport,
    *,
    parity: Status,
    artifact: Status,
    supported: bool = True,
) -> Eligibility:
    blockers: list[Block] = []
    if (
        report.capture != "VERIFIED"
        or report.stream != "VERIFIED"
        or report.counter.status != "VERIFIED"
        or report.gaps != 0
    ):
        blockers.append("BLOCKED_CAPTURE_INTEGRITY")
    if not supported or flow.feature_integrity == "FAILED":
        blockers.append("BLOCKED_UNSUPPORTED_INPUT")
    if flow.completeness != "VERIFIED":
        blockers.append("BLOCKED_FLOW_INCOMPLETE")
    if parity != "VERIFIED" or flow.feature_integrity != "VERIFIED":
        blockers.append("BLOCKED_FEATURE_PARITY")
    if artifact != "VERIFIED":
        blockers.append("BLOCKED_ARTIFACT")
    # Current policy has no Native admission path even for a fixture that models
    # every technical prerequisite. A future policy change requires separate review.
    blockers.append("BLOCKED_POLICY")
    return Eligibility(decision=blockers[0], blockers=tuple(blockers))


def offline_eligibility(flow: FlowReport, *, parity: Status, artifact: Status) -> Eligibility:
    """Diagnostic projection AFTER existing offline source/reference admission.

    This is never permission to execute a model. The worker still verifies the
    artifact, independent ML reference, input provenance and policy itself.
    """
    blockers: list[Block] = []
    if flow.feature_integrity != "VERIFIED":
        blockers.append("BLOCKED_UNSUPPORTED_INPUT")
    if flow.completeness != "VERIFIED":
        blockers.append("BLOCKED_FLOW_INCOMPLETE")
    if parity != "VERIFIED":
        blockers.append("BLOCKED_FEATURE_PARITY")
    if artifact != "VERIFIED":
        blockers.append("BLOCKED_ARTIFACT")
    return Eligibility(decision=blockers[0] if blockers else "ELIGIBLE", blockers=tuple(blockers))
