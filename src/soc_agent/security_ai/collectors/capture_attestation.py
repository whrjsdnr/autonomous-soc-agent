"""Strict proposed same-handle evidence validation; no Native admission authority."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen, digest


class CaptureScope(Frozen):
    session_id: UUID
    collector_identity: Hash
    image_digest: Hash
    interface: Literal["lo"]
    interface_identity: Hash
    net_namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    handle_identity: Hash
    handle_generation: UUID
    provider_digest: Hash
    counter_source: Literal["LIBPCAP_SAME_HANDLE_PROPOSED"]
    semantics: Literal["CUMULATIVE", "RESET_ON_READ"]
    counter_bits: Literal[32, 64]


class CaptureSample(Frozen):
    scope: CaptureScope
    sequence: int = Field(ge=1, le=602, strict=True)
    phase: Literal["START", "INTERVAL", "END"]
    retrieval: Literal["SUCCESS", "FAILED", "UNSUPPORTED", "UNKNOWN"]
    monotonic_ns: int = Field(ge=0, strict=True)
    observed_at: datetime
    received: int | None = Field(default=None, ge=0, strict=True)
    dropped: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def query_contract(self):
        if self.observed_at.tzinfo is None:
            raise ValueError("ATTESTATION_UTC_REQUIRED")
        if self.retrieval == "SUCCESS":
            if self.received is None or self.dropped is None:
                raise ValueError("ATTESTATION_SUCCESS_COUNTER_MISSING")
            if max(self.received, self.dropped) >= 2**self.scope.counter_bits:
                raise ValueError("ATTESTATION_COUNTER_WIDTH")
        elif self.received is not None or self.dropped is not None:
            raise ValueError("ATTESTATION_UNKNOWN_IS_NOT_ZERO")
        return self


def validate_fixture(
    scope: CaptureScope,
    samples: tuple[CaptureSample, ...],
    *,
    first_delivery_ns: int,
    last_delivery_ns: int,
    gaps: int | None,
    process_verified: bool,
    stream_verified: bool,
) -> dict:
    """Proposed provider conformance only. Caller-supplied evidence is not attestation."""
    result = dict(
        status="UNVERIFIED",
        reason="MISSING_WINDOW",
        counter_delta=None,
        drop_count=None,
        gap_count=gaps,
        retrieval="UNKNOWN",
        same_handle="NOT_OBSERVED",
        evidence_digest=digest([s.model_dump(mode="json") for s in samples]),
        scope="SYNTHETIC_PROVIDER_CONFORMANCE_NOT_NATIVE_PROOF",
        native_ai="BLOCKED",
    )
    if not 2 <= len(samples) <= 602:
        return result
    previous = None
    received = dropped = 0
    for i, sample in enumerate(samples, 1):
        if (
            sample.scope != scope
            or sample.sequence != i
            or sample.phase != ("START" if i == 1 else "END" if i == len(samples) else "INTERVAL")
        ):
            return {**result, "status": "FAILED", "reason": "HANDLE_SCOPE_OR_SEQUENCE_MISMATCH"}
        if previous and sample.monotonic_ns < previous.monotonic_ns:
            return {**result, "status": "FAILED", "reason": "PROCESS_TIME_REGRESSION"}
        if sample.retrieval != "SUCCESS":
            return {
                **result,
                "status": "FAILED" if sample.retrieval == "FAILED" else "UNVERIFIED",
                "retrieval": sample.retrieval,
                "reason": "COUNTER_RETRIEVAL_NOT_VERIFIED",
            }
        if (
            previous
            and scope.semantics == "CUMULATIVE"
            and (sample.received < previous.received or sample.dropped < previous.dropped)
        ):
            return {**result, "status": "FAILED", "reason": "RESET_OR_WRAP_UNATTESTED"}
        received = (
            received + sample.received if scope.semantics == "RESET_ON_READ" else sample.received
        )
        dropped = dropped + sample.dropped if scope.semantics == "RESET_ON_READ" else sample.dropped
        previous = sample
    if not (
        samples[0].monotonic_ns <= first_delivery_ns <= last_delivery_ns <= samples[-1].monotonic_ns
    ):
        return {**result, "reason": "CAPTURE_WINDOW_NOT_COVERED"}
    if not process_verified or not stream_verified or gaps is None:
        return {**result, "reason": "PROCESS_STREAM_OR_GAP_UNVERIFIED"}
    # Cumulative includes counts already reported at START; no initial losses are hidden.
    delta = received if scope.semantics == "RESET_ON_READ" else received - samples[0].received
    return {
        **result,
        "status": "FAILED" if dropped or gaps else "VERIFIED",
        "reason": "LOSS_DETECTED" if dropped or gaps else "FIXTURE_WINDOW_CONFORMANT",
        "retrieval": "SUCCESS",
        "same_handle": "FIXTURE_DECLARATION_ONLY",
        "counter_delta": delta,
        "drop_count": dropped,
    }


def report(collector, stream=None) -> dict:
    """Project the actually available stock-image evidence. Never accepts a sidecar claim."""
    c = collector
    stream = stream or c.stream
    counter = (c.native_integrity or {}).get("session", {}).get("counter", {})
    value = dict(
        contract="soc-zeek-capture-attestation:v1",
        session_id=str(c.plan.session_id),
        collector_identity=c.plan.identity,
        image_digest=c.plan.image.rsplit("sha256:", 1)[1],
        interface=c.plan.interface,
        interface_identity=None,
        net_namespace=c.plan.net_namespace,
        handle_identity=None,
        counter_source="ZEEK_GET_NET_STATS_NO_SUCCESS_SIGNAL",
        retrieval="UNKNOWN",
        snapshot_start=None,
        snapshot_end=None,
        counter_delta=None,
        drop_count=None,
        gap_count=None,
        reported_zeek_drops=counter.get("reported_drops"),
        verdict="FAILED"
        if counter.get("status") == "FAILED"
        or (c.native_integrity or {}).get("session", {}).get("capture") == "FAILED"
        else "UNVERIFIED",
        same_handle_proof="BLOCKED_STOCK_SOURCE_PRIVATE_HANDLE",
        packet_records=stream.observation_count if stream and stream.ready else None,
        packet_accounting_scope="ZEEK_DELIVERED_METADATA_NOT_KERNEL_OBSERVATIONS",
        native_ai="BLOCKED",
        provider_admission="NO_REVIEWED_NATIVE_PROVIDER",
        timestamp=None,
        timestamp_scope="BOUND_AUDIT_UTC_NOT_COUNTER_QUERY_TIME",
    )
    return {**value, "evidence_digest": digest(value)}
