"""Network14 input evidence receipts, independent of permission to run a model.

Only authenticated PacketChannel capture assessments are composed by Supervisor.
Synthetic assessments are usable for contract tests, never relabelled Native.
No model loading, inference, authentication or capture occurs here.
"""

import struct

from soc_agent.security_ai.collectors.parity import NETWORK14
from soc_agent.security_ai.ebpf.eligibility import float32_value
from soc_agent.security_ai.research.models import digest

# Ordered names from the digest-validated packaged catalogue. Bind the schema
# inside the approved runtime module, without a mutable file lookup on snapshot.
MODEL_ORDERED_NAMES_DIGEST = "047161f0114b667a1b4a3450af28e14390457b8ccbf320b1695e1e27aee32d67"


def input_receipts(summary: dict, transport: dict) -> list[dict]:
    capture = transport.get("capture_evidence") or {}
    window = capture.get("window_evidence") or {}
    provenance = capture.get("source_provenance") or {}
    plan = summary.get("plan") or {}
    names = [n for n, _, _ in NETWORK14]
    rows = list(summary.get("feature_tail") or [])
    # Retain one receipt for every candidate, without inventing missing raw vectors.
    # Raw vectors remain bounded to the tail; retained eligibility flags are not proof.
    represented = {r.get("flow_id") for r in rows}
    retained = summary.get("candidate_eligibility") or []
    rows = [r for r in retained if r.get("flow_id") not in represented] + rows
    duplicates = {
        r.get("flow_id")
        for r in rows
        if sum(x.get("flow_id") == r.get("flow_id") for x in rows) > 1
    }
    receipts = []
    for row in rows:
        reasons = []
        state = "INCOMPLETE"
        values = row.get("values")
        valid = bool(
            isinstance(values, (list, tuple))
            and len(values) == 14
            and all(float32_value(v) for v in values)
        )
        if values is None:
            state = "UNKNOWN"
            reasons.append("RAW_VECTOR_NOT_RETAINED")
        elif (
            not valid
            or row.get("feature_names") != names
            or digest(names) != MODEL_ORDERED_NAMES_DIGEST
        ):
            state = "INVALID"
            reasons.append("NETWORK14_SCHEMA_INVALID")
        elif digest(values) != row.get("values_digest"):
            state = "INVALID"
            reasons.append("FEATURE_FINGERPRINT_MISMATCH")
        flow_id = row.get("flow_id")
        if (
            not isinstance(flow_id, str)
            or len(flow_id) != 64
            or any(c not in "0123456789abcdef" for c in flow_id)
        ):
            state = "INVALID"
            reasons.append("FLOW_IDENTITY_INVALID")
        if type(row.get("packet_count")) is not int or not 1 <= row["packet_count"] <= 4096:
            state = "INVALID"
            reasons.append("FLOW_PACKET_COUNT_INVALID")
        if capture.get("status") == "INVALID" or window.get("status") == "INVALID":
            state = "INVALID"
            reasons.append("CAPTURE_EVIDENCE_INVALID")
        if row.get("flow_id") in duplicates:
            state = "INVALID"
            reasons.append("DUPLICATE_FLOW_EXPORT")
        if capture.get("status") != "VERIFIED" or window.get("status") != "VERIFIED":
            reasons.append("CAPTURE_WINDOW_INCOMPLETE")
        if window and window.get("digest") != digest(
            {k: v for k, v in window.items() if k != "digest"}
        ):
            state = "INVALID"
            reasons.append("WINDOW_DIGEST_MISMATCH")
        if not provenance or not all(
            (
                provenance.get("session") == plan.get("session_id")
                and bool(plan.get("session_id")),
                provenance.get("generation") == plan.get("generation")
                and bool(plan.get("generation")),
                provenance.get("plan_digest") == summary.get("plan_digest")
                and bool(summary.get("plan_digest")),
                provenance.get("program_sha256") == plan.get("program_sha256")
                and bool(plan.get("program_sha256")),
                provenance.get("approval_digest") == plan.get("source_digest")
                and bool(plan.get("source_digest")),
            )
        ):
            reasons.append("SOURCE_PROVENANCE_MISSING_OR_MISMATCH")
        lifecycle = row.get("lifecycle") or {}
        first, last, witness = (
            lifecycle.get(k) for k in ("first_event_ns", "last_event_ns", "timeout_witness_ns")
        )
        inside = all(type(v) is int for v in (first, last, witness)) and (
            window.get("start_bound_ns", 0)
            <= first
            <= last
            <= witness
            <= window.get("end_bound_ns", -1)
        )
        close = row.get("close_reason")
        timeout = (
            inside
            and lifecycle.get("termination_authority") == "OBSERVED_EVENT_TIMEOUT"
            and (
                close == "IDLE_TIMEOUT"
                and witness - last >= 30_000_000_000
                or close == "ACTIVE_TIMEOUT"
                and witness - first >= 120_000_000_000
            )
        )
        if not timeout:
            reasons.append("FLOW_TIMEOUT_OR_WINDOW_NOT_PROVEN")
        if valid and (
            any(v < 0 for v in values)
            or any(values[i] != int(values[i]) for i in (1, 2, 3, 4, 5, 6, 9, 10, 11))
        ):
            state = "INVALID"
            reasons.append("FEATURE_UNIT_OR_RANGE_INVALID")
        if (
            valid
            and all(type(v) is int for v in (first, last))
            and (values[0] != struct.unpack("!f", struct.pack("!f", (last - first) / 1e9))[0])
        ):
            state = "INVALID"
            reasons.append("FEATURE_DURATION_MISMATCH")
        if valid and row.get("packet_count") != values[1] + values[2]:
            state = "INVALID"
            reasons.append("FLOW_FEATURE_COUNT_MISMATCH")
        ordering = summary.get("ordering") or {}
        if (
            ordering.get("late_events", 0)
            or summary.get("last_error")
            or any(summary.get(k) for k in ("queue_rejected", "queue_discarded"))
        ):
            reasons.append("PROCESSING_OR_CLOCK_FAILURE")
        if not reasons:
            state = "ELIGIBLE"
        body = dict(
            contract="soc-network14-input-evidence:v1",
            flow_id=row.get("flow_id"),
            input_state=state,
            eligible=state == "ELIGIBLE",
            reasons=reasons,
            source=capture.get("source", "UNKNOWN"),
            capture_window_digest=window.get("digest"),
            feature_fingerprint=row.get("values_digest"),
            feature_schema_digest=digest(names),
            source_provenance=provenance,
            flow_completion="COMPLETE" if timeout else "INCOMPLETE",
            native_ai="BLOCKED",
            dns9="BLOCKED",
            model_executed=False,
            model_artifact_validation="NOT_PERFORMED",
            scope="INPUT_EVIDENCE_ONLY_NOT_INFERENCE_OR_OPERATIONAL_APPROVAL",
        )
        receipts.append(body | dict(receipt_digest=digest(body)))
    return receipts
