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
    retained = summary.get("candidate_eligibility") or []
    retained = [r for r in retained if isinstance(r, dict) and r.get("flow_id")]
    if len(retained) > len(rows):
        # The checkpoint retains bounded RCA receipts for all candidates but raw
        # feature vectors only for the tail. Do not discard those receipts when
        # adding final transport evidence, or pretend to revalidate absent vectors.
        vectors = {r.get("flow_id"): r for r in rows}
        rows = [vectors.get(r["flow_id"], r) for r in retained]
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
        accounting = transport.get("capture_evidence") or {}
        if emitted is not None and delivered is not None and emitted != delivered:
            excluded = (transport.get("delivery_accounting") or {}).get("budget_excluded")
            if (
                accounting.get("counter_reconciliation") == "RECONCILED"
                and excluded == emitted - delivered
            ):
                reasons.append("CAPTURE_BUDGET_EXCLUDED")
            else:
                reasons.append("EMITTED_DELIVERY_NOT_RECONCILED")
        retained_receipt = "values" not in row and "network14_float32_contract" in row
        values = row.get("values")
        if retained_receipt:
            contract = row.get("network14_float32_contract") is True
            values_digest = row.get("values_digest_valid") is True
            reasons.append("RAW_VECTOR_NOT_RETAINED_CHECKPOINT_RECEIPT_ONLY")
        else:
            contract = (
                row.get("feature_names") == [entry[0] for entry in NETWORK14]
                and isinstance(values, (list, tuple))
                and len(values) == 14
                and all(float32_value(v) for v in values)
            )
            try:
                values_digest = (
                    isinstance(values, (list, tuple))
                    and bool(values)
                    and digest(values) == row.get("values_digest")
                )
            except (ValueError, TypeError, OverflowError):
                values_digest = False  # Non-canonical/non-finite input is INVALID, never imputed.
        if not contract or not values_digest:
            reasons.append("MODEL_INPUT_CONTRACT_OR_DIGEST_INVALID")
        if "values" not in row and not retained_receipt:
            input_state = "UNKNOWN"
        elif not contract or not values_digest:
            input_state = "INVALID"
        elif (
            close not in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"}
            or row.get("flow_completeness") != "CANDIDATE_TIMEOUT"
            or any(
                r in reasons
                for r in (
                    "SOCKET_DELIVERY_FAILED",
                    "PROCESSING_DISCARDED",
                    "QUEUE_REJECTED",
                    "RING_RESERVATION_LOSS",
                    "LATE_EVENT",
                    "UNRECONCILED_CPU_OBSERVATION_ATTEMPTS",
                )
            )
        ):
            input_state = "INCOMPLETE"
        else:
            input_state = "UNKNOWN"  # Capture/parity/model evidence is still unproven.
        reasons.extend(["NATIVE_GOLDEN_PARITY_UNKNOWN", "MODEL_ARTIFACT_RECEIPT_UNKNOWN"])
        result.append(
            dict(
                flow_id=row.get("flow_id"),
                close_reason=close,
                flow_completeness=row.get("flow_completeness", "UNKNOWN"),
                packet_count=row.get("packet_count"),
                lifecycle=row.get("lifecycle"),
                values_digest=row.get("values_digest"),
                values_digest_valid=values_digest,
                network14_float32_contract=contract,
                vector_validation_source="CHECKPOINT_RECEIPT" if retained_receipt else "VALUES",
                input_state=input_state,
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
                input_state="UNKNOWN",
                reasons=["HISTORICAL_CANDIDATE_DETAILS_UNKNOWN"],
                eligible=False,
            )
        )
    return result
