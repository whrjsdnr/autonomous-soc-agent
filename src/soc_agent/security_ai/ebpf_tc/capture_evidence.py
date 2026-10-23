"""Terminal metadata accounting, separate from capture completeness and AI gates."""

import struct

ACCOUNTING = struct.Struct("<9Qq")


def decode_accounting(raw: bytes) -> dict:
    if len(raw) != ACCOUNTING.size:
        raise ValueError("TCX_ACCOUNTING_SCHEMA")
    fields = ACCOUNTING.unpack(raw)
    version, generation, callbacks, delivered, excluded, invalid, failed, start, stop, drain = (
        fields
    )
    if (
        version != 1
        or generation == 0
        or delivered > 4096
        or not 0 < start <= stop
        or drain > 0
        or callbacks != delivered + excluded + invalid + failed
    ):
        raise ValueError("TCX_ACCOUNTING_SCHEMA")
    return dict(
        generation=generation,
        callbacks=callbacks,
        delivered=delivered,
        budget_excluded=excluded,
        invalid=invalid,
        send_failed=failed,
        start_config_ns=start,
        final_drain_started_ns=stop,
        drain_result=drain,
        clock_domain="KERNEL_MONOTONIC_NS",
        boundary_scope="CONFIG_START_AND_FINAL_DRAIN_UPPER_BOUND_NOT_ATOMIC_CAPTURE_WINDOW",
    )


def assess_capture(
    counters: dict | None,
    delivery: dict | None,
    processing: dict | None,
    *,
    closed: bool,
    error: str | None,
    source: int,
    scope: dict,
    cpu_windows: list | None = None,
    clock_samples: list | None = None,
) -> dict:
    """Never turn a final aggregate snapshot into proof of an entire window."""
    reasons = []
    totals = (counters or {}).get("totals") or {}
    generation = (processing or {}).get("plan", {}).get("generation")
    same_epoch = bool(
        generation
        and counters
        and delivery
        and generation == counters.get("generation") == delivery.get("generation")
    )
    if not same_epoch:
        reasons.append("COUNTER_EPOCH_MISSING_OR_MISMATCH")
    if not counters or counters.get("retrieval") != "SUCCESS":
        reasons.append("KERNEL_COUNTER_UNKNOWN")
    if delivery is None:
        reasons.append("DELIVERY_ACCOUNTING_NOT_OBSERVED")
    if not closed:
        reasons.append("CLOSED_NOT_OBSERVED")
    if error:
        reasons.append("PROCESSING_OR_CLEANUP_ERROR")
    balance = "UNKNOWN"
    required = {
        "observed",
        "emitted",
        "ring_reservation_failures",
        "unsupported",
        "malformed",
        "disabled",
        "budget",
    }
    complete = required <= totals.keys() and all(
        type(totals[k]) is int and totals[k] >= 0 for k in required
    )
    if same_epoch and complete:
        population = sum(
            totals[k]
            for k in (
                "emitted",
                "ring_reservation_failures",
                "unsupported",
                "malformed",
                "disabled",
                "budget",
            )
        )
        matched = (
            totals.get("observed") == population
            and totals.get("emitted") == delivery["callbacks"]
            and counters["delivered"] == delivery["delivered"]
            and delivery["delivered"] == (processing or {}).get("received")
            and delivery["drain_result"] == 0
        )
        balance = "RECONCILED" if matched else "MISMATCH"
        if not matched:
            reasons.append("COUNTER_POPULATIONS_NOT_RECONCILED")
        for key in ("ring_reservation_failures", "malformed", "unsupported", "budget"):
            if totals.get(key):
                reasons.append("KERNEL_" + key.upper())
        for key in ("budget_excluded", "invalid", "send_failed"):
            if delivery[key]:
                reasons.append("DELIVERY_" + key.upper())
    if processing:
        if processing.get("accepted") != processing.get("received") or processing.get("last_error"):
            reasons.append("PROCESSING_NOT_FULLY_APPLIED")
        if processing.get("queue_discarded") or processing.get("queue_rejected"):
            reasons.append("PROCESSING_DISCARDED_OR_REJECTED")
        if (processing.get("cpu_sequence") or {}).get("unrepresented_attempts"):
            reasons.append("CPU_ATTEMPT_GAPS_UNRECONCILED")
        if (processing.get("ordering") or {}).get("late_events"):
            reasons.append("LATE_EVENT")
    # A zero final total is not a start snapshot, a per-CPU interval, or calibrated clock.
    reasons.extend(
        [
            "ATOMIC_CAPTURE_WINDOW_NOT_ATTESTED",
            "INITIAL_PER_CPU_BASELINE_NOT_OBSERVED",
            "CLOCK_CALIBRATION_NOT_ATTESTED",
            "KERNEL_WIDE_DROPS_UNKNOWN",
        ]
    )
    from soc_agent.security_ai.ebpf_tc.window_evidence import assess_windows

    window = assess_windows(
        cpu_windows or [], processing or {}, totals, delivery or {}, clock_samples
    )
    # Observed sub-evidence remains observed even when another window gate fails.
    # This changes diagnostics only; the complete window still gates eligibility.
    if window.get("initial_baseline") == "VERIFIED_ZERO_OWNED_MAP":
        reasons.remove("INITIAL_PER_CPU_BASELINE_NOT_OBSERVED")
    if window.get("clock", {}).get("status") == "VERIFIED":
        reasons.remove("CLOCK_CALIBRATION_NOT_ATTESTED")
    if window["status"] == "VERIFIED" and balance == "RECONCILED":
        # Per-CPU emitted == received, stable zero baseline, all branch populations
        # and paired clock brackets prove the owned hook, not pre-hook traffic.
        reconciled = {
            "ATOMIC_CAPTURE_WINDOW_NOT_ATTESTED",
            "INITIAL_PER_CPU_BASELINE_NOT_OBSERVED",
            "CLOCK_CALIBRATION_NOT_ATTESTED",
            "KERNEL_WIDE_DROPS_UNKNOWN",
            "CPU_ATTEMPT_GAPS_UNRECONCILED",
        }
        reasons = [r for r in reasons if r not in reconciled]
    return dict(
        window_evidence=window,
        status="INVALID"
        if window["status"] == "INVALID"
        else "VERIFIED"
        if window["status"] == "VERIFIED" and not reasons
        else "INCOMPLETE",
        counter_reconciliation=balance,
        same_epoch=same_epoch,
        source="KERNEL_TCX_NATIVE" if source == 1 else "FIXTURE_NOT_NATIVE",
        source_provenance=scope
        | dict(
            plan_digest=(processing or {}).get("plan_digest"),
            session=(processing or {}).get("plan", {}).get("session_id"),
            generation=generation,
            namespace=(processing or {}).get("plan", {}).get("net_namespace"),
            interface=(processing or {}).get("plan", {}).get("interface"),
            hook=(processing or {}).get("plan", {}).get("hook"),
        ),
        reasons=reasons,
        scope="OWNED_HOOK_SUPPORTED_METADATA_ONLY",
        kernel_wide_drops="UNKNOWN",
        native_ai="BLOCKED",
    )
