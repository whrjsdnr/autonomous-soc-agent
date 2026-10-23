"""Bounded, same-owned-map CPU snapshots. No inference of unobserved CPU activity.

PRE_ATTACH/POST_DETACH rows bracket a stable map lookup, not an atomic live
snapshot. This proves the owned program's lifetime only, never pre-hook packets,
UTC calibration, system-wide drops, or coverage beyond the delivered prefix.
"""

import struct

from soc_agent.security_ai.research.models import digest

CPU_WINDOW = struct.Struct("<II9Q")
COUNTERS = (
    "observed",
    "emitted",
    "ring_reservation_failures",
    "unsupported",
    "malformed",
    "disabled",
    "budget",
)


def decode_cpu_window(raw: bytes) -> dict:
    if len(raw) != 80:
        raise ValueError("TCX_CPU_WINDOW_SIZE")
    cpu, flags, before, after, *counts = CPU_WINDOW.unpack(raw)
    phase, count = flags & 65535, flags >> 16
    if phase not in {1, 2} or not 1 <= count <= 128 or cpu >= count or not 0 < before <= after:
        raise ValueError("TCX_CPU_WINDOW_SCHEMA")
    if counts[0] != sum(counts[1:]):
        raise ValueError("TCX_CPU_WINDOW_POPULATION")
    return dict(
        cpu=cpu,
        possible_cpus=count,
        phase="PRE_ATTACH" if phase == 1 else "POST_DETACH",
        before_ns=before,
        after_ns=after,
        counters=dict(zip(COUNTERS, counts, strict=True)),
    )


def accept_cpu_window(rows: list, raw: bytes) -> None:
    value = decode_cpu_window(raw)
    count = value["possible_cpus"]
    index = len(rows)
    if index >= 2 * count or rows and count != rows[0]["possible_cpus"]:
        raise ValueError("TCX_CPU_WINDOW_BOUND")
    if value["cpu"] != index % count or value["phase"] != (
        "PRE_ATTACH" if index < count else "POST_DETACH"
    ):
        raise ValueError("TCX_CPU_WINDOW_SEQUENCE")
    if (
        index
        and index % count
        and (value["before_ns"], value["after_ns"]) != (rows[-1]["before_ns"], rows[-1]["after_ns"])
    ):
        raise ValueError("TCX_CPU_WINDOW_LOOKUP_IDENTITY")
    rows.append(value)


def assess_windows(
    rows: list, processing: dict, totals: dict, delivery: dict, clock_samples: list | None = None
) -> dict:
    """Called only after credential/approval/session/generation wire validation.

    Samples are not accepted from a caller-provided VERIFIED flag. Missing,
    reset, mismatched and non-monotonic evidence remain distinct failures.
    """
    reasons = []
    cpus = rows[0]["possible_cpus"] if rows else 0
    if not cpus or len(rows) != 2 * cpus:
        return dict(status="INCOMPLETE", reasons=["CPU_BOUNDARIES_MISSING"], cpus=[])
    initial, final = rows[:cpus], rows[cpus:]
    intervals = (processing.get("cpu_sequence") or {}).get("intervals", {})
    # Keep the producer's actual observed fields; no idle CPU timestamps are invented.
    if isinstance(intervals, list):
        intervals = {str(x["cpu"]): x for x in intervals}
    if any(not k.isdecimal() or int(k) >= cpus for k in intervals):
        reasons.append("CPU_OUTSIDE_ATTESTED_SET")
    if sum(r.get("received", 0) for r in intervals.values()) != processing.get("received"):
        reasons.append("CPU_RECEIVE_POPULATION_MISMATCH")
    reports = []
    sums = dict.fromkeys(COUNTERS, 0)
    start, stop = initial[-1]["after_ns"], final[0]["before_ns"]
    if start > stop:
        reasons.append("CLOCK_BOUNDARY_REGRESSION")
    for a, b in zip(initial, final, strict=True):
        cpu = a["cpu"]
        delta = {k: b["counters"][k] - a["counters"][k] for k in COUNTERS}
        if any(a["counters"].values()):
            reasons.append("INITIAL_OWNED_MAP_NOT_ZERO")
        if any(x < 0 for x in delta.values()):
            reasons.append("COUNTER_REGRESSION_OR_EPOCH_MISMATCH")
        for k in COUNTERS:
            sums[k] += delta[k]
        received = intervals.get(str(cpu), {})
        if delta["emitted"] != received.get("received", 0):
            reasons.append("CPU_EMITTED_DELIVERY_MISMATCH")
        if received and not (
            start <= received.get("first_ns", -1) <= received.get("last_ns", -1) <= stop
        ):
            reasons.append("CPU_EVENT_OUTSIDE_BOUNDARIES")
        for k in ("ring_reservation_failures", "unsupported", "malformed", "budget"):
            if delta[k]:
                reasons.append("CPU_" + k.upper())
        reports.append(
            dict(
                cpu=cpu,
                counters=delta,
                activity=(
                    "NO_OWNED_HOOK_ATTEMPTS"
                    if delta["observed"] == 0
                    else "EMITTED_METADATA"
                    if delta["emitted"]
                    else "NON_EMITTING_ATTEMPTS"
                ),
            )
        )
    if sums != totals:
        reasons.append("PER_CPU_AGGREGATE_MISMATCH")
    if any(delivery.get(k) for k in ("budget_excluded", "invalid", "send_failed")):
        reasons.append("DELIVERED_WINDOW_TRUNCATED")
    clock = processing.get("clock") or {}
    if clock.get("domain") != "KERNEL_MONOTONIC_NS":
        reasons.append("CLOCK_DOMAIN_MISMATCH")
    # Brackets attest relative event containment, not calibrated clock accuracy.
    clock_evidence = assess_clock(clock_samples or [], processing)
    if clock_evidence["status"] != "VERIFIED":
        reasons.append("KERNEL_USER_CLOCK_CALIBRATION_NOT_OBSERVED")
    body = dict(
        status="INVALID"
        if any("REGRESSION" in x for x in reasons)
        else "INCOMPLETE"
        if reasons
        else "VERIFIED",
        initial_baseline=(
            "VERIFIED_ZERO_OWNED_MAP"
            if not any(any(r["counters"].values()) for r in initial)
            else "INVALID_NONZERO_OWNED_MAP"
        ),
        clock=clock_evidence,
        reasons=sorted(set(reasons)),
        start_bound_ns=start,
        end_bound_ns=stop,
        cpus=reports,
        clock_domain=clock.get("domain"),
        scope="OWNED_HOOK_SUPPORTED_METADATA_NOT_SYSTEM_WIDE_CAPTURE",
        utc_calibration="UNKNOWN",
        native_ai="BLOCKED",
    )
    return body | dict(digest=digest(body))


def decode_clock_sample(raw: bytes) -> dict:
    from soc_agent.security_ai.ebpf.clock import ClockSample

    if len(raw) != 80:
        raise ValueError("TCX_CLOCK_SAMPLE_SIZE")
    version, phase, generation, before, wall, after, *reserved = struct.unpack("<10Q", raw)
    if version != 1 or phase not in {1, 2} or not generation or any(reserved):
        raise ValueError("TCX_CLOCK_SAMPLE_SCHEMA")
    sample = ClockSample(before_ns=before, wall_ns=wall, after_ns=after)
    return dict(phase=phase, generation=generation, **sample.model_dump())


def accept_clock_sample(rows: list, raw: bytes, generation: int) -> None:
    sample = decode_clock_sample(raw)
    if len(rows) >= 6 or sample["phase"] != (1 if len(rows) < 3 else 2):
        raise ValueError("TCX_CLOCK_SAMPLE_SEQUENCE")
    if sample["generation"] != generation or rows and sample["before_ns"] < rows[-1]["after_ns"]:
        raise ValueError("TCX_CLOCK_SAMPLE_EPOCH_OR_REGRESSION")
    rows.append(sample)


def assess_clock(samples: list, processing: dict) -> dict:
    if len(samples) != 6:
        return dict(status="INCOMPLETE", reason="CLOCK_BOUNDARY_SAMPLES_MISSING")
    generation = processing.get("plan", {}).get("generation")
    if any(s["generation"] != generation for s in samples):
        return dict(status="INVALID", reason="CLOCK_EPOCH_MISMATCH")
    low = max(s["wall_ns"] - s["after_ns"] for s in samples)
    high = min(s["wall_ns"] - s["before_ns"] for s in samples)
    if any(a["after_ns"] > b["before_ns"] for a, b in zip(samples, samples[1:], strict=False)):
        return dict(status="INVALID", reason="CLOCK_SAMPLE_REGRESSION")
    intervals = (processing.get("cpu_sequence") or {}).get("intervals") or {}
    if any(
        not (samples[2]["after_ns"] <= r["first_ns"] <= r["last_ns"] <= samples[3]["before_ns"])
        for r in intervals.values()
    ):
        return dict(status="INCOMPLETE", reason="CLOCK_SAMPLES_DO_NOT_ENCLOSE_EVENTS")
    if low > high:
        return dict(status="INVALID", reason="CLOCK_OFFSET_INTERVAL_DISJOINT")
    return dict(
        status="VERIFIED",
        domain="KERNEL_MONOTONIC_NS",
        epoch=generation,
        offset_interval_ns=[low, high],
        authority="AUTHENTICATED_BROKER_MONOTONIC_REALTIME_BRACKETS",
        scope="SAME_HOST_DECLARED_KERNEL_DOMAIN_NOT_EXTERNAL_CLOCK_ACCURACY",
    )


def observation_budget(processing: dict, transport: dict) -> dict:
    """Explain event-time exhaustion; this diagnostic never authorizes capture or AI.

    Waiting after STOP cannot advance the producer's observed-event watermark.
    A sufficient duration alone proves neither loss-free capture nor a timeout.
    """
    plan = processing.get("plan") or {}
    delivery = transport.get("delivery_accounting") or {}
    intervals = (processing.get("cpu_sequence") or {}).get("intervals") or {}
    rows = list(intervals.values()) if isinstance(intervals, dict) else intervals
    bounds = [(r.get("first_ns"), r.get("last_ns")) for r in rows if isinstance(r, dict)]
    complete = (
        bool(bounds)
        and len(bounds) == len(rows)
        and all(type(a) is int and type(b) is int and 0 <= a <= b for a, b in bounds)
    )
    span = max(b for _, b in bounds) - min(a for a, _ in bounds) if complete else None
    received, limit = processing.get("received"), plan.get("event_limit")
    valid_count = (
        type(received) is int and type(limit) is int and limit == 4096 and 0 <= received <= limit
    )
    cap = received == limit if valid_count else None
    epoch = bool(plan.get("generation")) and plan.get("generation") == delivery.get("generation")
    state = (
        "UNKNOWN"
        if span is None or not valid_count or not epoch
        else "CAP_REACHED_BEFORE_MINIMUM_IDLE_SPAN"
        if cap and span < 30_000_000_000
        else "OBSERVED_SPAN_BELOW_MINIMUM_IDLE"
        if span < 30_000_000_000
        else "EVENT_SPAN_SUFFICIENT_DURATION_ONLY"
    )
    return dict(
        contract="soc-capture-observation-budget:v1",
        state=state,
        observed_event_span_ns=span,
        event_limit_reached=cap,
        received=received,
        event_limit=limit,
        same_counter_epoch=epoch,
        clock_domain=(processing.get("clock") or {}).get("domain"),
        timeout_authority="OBSERVED_EVENT_WATERMARK",
        idle_timeout_ns=30_000_000_000,
        active_timeout_ns=120_000_000_000,
        post_stop_wall_clock_completes_flow=False,
        rate_control="NONE_IN_CURRENT_FULL_SCOPE_CAPTURE_CONTRACT",
        capture_integrity=(transport.get("capture_evidence") or {}).get("status", "UNKNOWN"),
        completion_or_eligibility_proven=False,
        scope="DURATION_DIAGNOSTIC_ONLY_NOT_A_CAPTURE_OR_ELIGIBILITY_DECISION",
        native_ai="BLOCKED",
    )
