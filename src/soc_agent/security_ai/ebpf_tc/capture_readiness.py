"""Read-only ambient loopback budget diagnostics; never Capture or admission authority.

Interface RX includes traffic outside supported TCX metadata and is not an
emitted-event counter. A low measured rate cannot attest a future quiet Window.
"""

import time
from pathlib import Path


def loopback_snapshot() -> dict:
    root = Path("/sys/class/net/lo/statistics")
    return dict(
        monotonic_ns=time.monotonic_ns(),
        namespace=str(Path("/proc/self/ns/net").readlink()),
        rx_packets=int((root / "rx_packets").read_text()),
        rx_dropped=int((root / "rx_dropped").read_text()),
    )


def assess_loopback_budget(
    samples: list[dict], *, expected_namespace: str = "net:[4026531833]"
) -> dict:
    """Project ambient packet load against the existing 45s/4096 contract.

    No packet filtering, rate control or invented diagnostic-traffic allowance.
    Counter resets, namespace changes and short/missing samples fail closed.
    """
    result = dict(
        scope="LO_RX_ALL_PROTOCOLS_NOT_TCX_EMITTED",
        execution_ready=False,
        native_ai="BLOCKED",
        event_limit=4096,
        target_seconds=45,
        target_origin="TCP_CLOSE_NOT_CAPTURE_START",
        setup_duration_seconds="UNKNOWN_ADDITIONAL_BUDGET_REQUIRED",
        expected_namespace=expected_namespace,
        scenario_packets="NOT_BOUNDED_BY_PASSIVE_MEASUREMENT",
    )
    if len(samples) < 2:
        return result | dict(state="UNKNOWN", reason="INSUFFICIENT_SAMPLES")
    for row in samples:
        if (
            not isinstance(row, dict)
            or row.get("namespace") != result["expected_namespace"]
            or any(
                type(row.get(k)) is not int or row[k] < 0
                for k in ("monotonic_ns", "rx_packets", "rx_dropped")
            )
        ):
            return result | dict(state="UNKNOWN", reason="SAMPLE_IDENTITY_OR_SCHEMA")
    rates = []
    for a, b in zip(samples, samples[1:], strict=False):
        elapsed = b["monotonic_ns"] - a["monotonic_ns"]
        packets = b["rx_packets"] - a["rx_packets"]
        if elapsed <= 0 or packets < 0 or b["rx_dropped"] < a["rx_dropped"]:
            return result | dict(state="UNKNOWN", reason="COUNTER_RESET_OR_CLOCK_REGRESSION")
        rates.append(packets / (elapsed / 1e9))
    span = (samples[-1]["monotonic_ns"] - samples[0]["monotonic_ns"]) / 1e9
    packets = samples[-1]["rx_packets"] - samples[0]["rx_packets"]
    average = packets / span
    state = (
        "AMBIENT_RATE_EXCEEDS_BUDGET"
        if max(rates) * 45 >= 4096
        else "UNKNOWN_SHORT_OBSERVATION"
        if span < 35
        else "CONDITIONAL_MEASUREMENT_ONLY"
    )
    return result | dict(
        state=state,
        observation_seconds=span,
        observed_packets=packets,
        packet_rate_mean=average,
        packet_rate_min=min(rates),
        packet_rate_max=max(rates),
        projected_45s_packets_mean=average * 45,
        projected_45s_packets_peak=max(rates) * 45,
        seconds_to_limit_at_mean=4096 / average if average else None,
        interface_drop_delta=samples[-1]["rx_dropped"] - samples[0]["rx_dropped"],
        reason="NO_FUTURE_WINDOW_OR_FLOW_COMPLETENESS_ATTESTATION",
    )
