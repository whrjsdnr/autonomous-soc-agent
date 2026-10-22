"""Evidence-only candidate RCA. Never grants Native AI eligibility."""

import math
import struct

from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.research.models import digest


def float32_value(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and struct.unpack("<f", struct.pack("<f", value))[0] == value
    except (OverflowError, struct.error):
        return False


def candidate_rca(summary: dict, transport: dict | None = None) -> list[dict]:
    transport = transport or {}
    counters = transport.get("counter_evidence") or {}
    totals = counters.get("totals") or {}
    rows = summary.get("feature_tail", [])
    result = []
    for row in rows:
        reasons = ["CAPTURE_INTEGRITY_UNVERIFIED", "NATIVE_AI_POLICY_BLOCKED"]
        close = row.get("close_reason", "UNKNOWN")
        if (
            close not in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"}
            or row.get("flow_completeness") != "CANDIDATE_TIMEOUT"
        ):
            reasons.append("FLOW_NOT_PROVEN_COMPLETE:" + close)
        if (summary.get("cpu_sequence") or {}).get("unrepresented_attempts", 0):
            reasons.append("UNRECONCILED_CPU_OBSERVATION_ATTEMPTS")
        clock = summary.get("clock") or {}
        if clock.get("calibration") != "VERIFIED":
            reasons.append("CLOCK_CALIBRATION_UNVERIFIED")
        if (summary.get("ordering") or {}).get("late_events", 0):
            reasons.append("LATE_EVENT")
        if (
            transport.get("socket_send_failures")
            or summary.get("last_error") == "TCX_DATA_SOCKET_DELIVERY_LOSS"
        ):
            reasons.append("SOCKET_DELIVERY_FAILED")
        if summary.get("queue_discarded"):
            reasons.append("PROCESSING_DISCARDED")
        if summary.get("queue_rejected") or transport.get("queue_overflows"):
            reasons.append("QUEUE_REJECTED")
        ring = (
            totals.get("ring_reservation_failures")
            if counters.get("retrieval") == "SUCCESS"
            else None
        )
        if ring is None:
            reasons.append("RING_LOSS_UNKNOWN")
        elif ring:
            reasons.append("RING_RESERVATION_LOSS")
        emitted, delivered = totals.get("emitted"), counters.get("delivered")
        if emitted is not None and delivered is not None and emitted != delivered:
            reasons.append("EMITTED_DELIVERY_NOT_RECONCILED")
        values = row.get("values", [])
        contract = (
            row.get("feature_names") == [entry[0] for entry in NETWORK14]
            and len(values) == 14
            and all(float32_value(v) for v in values)
        )
        values_digest = bool(values) and digest(values) == row.get("values_digest")
        if not contract or not values_digest:
            reasons.append("MODEL_INPUT_CONTRACT_OR_DIGEST_INVALID")
        reasons.extend(["NATIVE_GOLDEN_PARITY_UNKNOWN", "MODEL_ARTIFACT_RECEIPT_UNKNOWN"])
        result.append(
            dict(
                flow_id=row.get("flow_id"),
                close_reason=close,
                packet_count=row.get("packet_count"),
                values_digest=row.get("values_digest"),
                values_digest_valid=values_digest,
                network14_float32_contract=contract,
                reasons=reasons,
                reason_scope="CANDIDATE_AND_SESSION_CONTEXT_NOT_PER_PACKET_ATTRIBUTION",
                ring_reservation_failures=ring,
                cpu_attempt_gaps=(summary.get("cpu_sequence") or {}).get("unrepresented_attempts"),
                bounded_clock_inversions=(summary.get("ordering") or {}).get("inversions"),
                eligible=False,
                native_ai="BLOCKED",
            )
        )
    missing = max(0, summary.get("finalized_count", len(rows)) - len(rows))
    if missing:
        result.append(
            dict(
                flow_id=None,
                unretained_candidates=missing,
                reasons=["HISTORICAL_CANDIDATE_DETAILS_UNKNOWN"],
                eligible=False,
            )
        )
    return result
