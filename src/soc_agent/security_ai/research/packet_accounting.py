"""Controller projection of attested counters; never changes helper admission policy."""

from collections.abc import Mapping


def observed_count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def packet_accounting(
    metrics: Mapping[str, object], *, origin: str, session_id: str | None = None
) -> dict:
    """Raw receive includes the rate-rejected frame; normalized != inferred duplicate.

    Kernel counters count kernel observations including frames not drained by the
    helper. Their difference from recv count is not itself evidence of a drop.
    Only explicit kernel drop counters establish that measurement.
    """
    get = lambda key: observed_count(metrics.get(key))  # noqa: E731
    if (
        metrics.get("integrity_scope") == "CAPTURE_WIDE"
        or metrics.get("capture_integrity") == "CAPTURE_INTEGRITY_FAILED"
    ):
        scope = "FAILED_SHARED_CAPTURE_WINDOW"
    elif metrics.get("abort_reason"):
        scope = "UNKNOWN"
    else:
        scope = "PREFIX_NOT_COMPLETION"
    result = {
        "contract": "soc-packet-accounting:v1",
        "origin": origin,
        "capture_session": session_id,
        "counter_sequence": get("counter_sequence"),
        "rate_budget_unit": "RAW_FRAME_BEFORE_DIRECTION_FILTER",
        "kernel_observed_raw_frames": get("kernel_packets_total"),
        "received_raw_frames": get("received_frames"),
        "accepted_raw_frames": None,  # No successful-consume counter in this wire contract.
        "loopback_duplicate_candidates": None,  # No pair identity/direction histogram on wire.
        "filtered_raw_frames": None,  # No classified exclusion counter on the approved wire.
        "analysis_scope": "ALL_APPROVED_NORMALIZED_TCP_UDP_UNCHANGED",
        "outbound_frames": None,
        "inbound_frames": None,
        "normalized_packets_sent": get("sent_packets"),
        "transport_delivered_packets": get("transport_delivered_packets"),
        "network_flow_inputs": get("packets_collected"),
        "dns_diagnostic_inputs": get("dns_diagnostic_inputs"),
        "capture_drops": get("capture_drops"),
        "capture_gaps": get("gap_count"),
        "counter_status": metrics.get("counter_status", "UNKNOWN"),
        "quality_scope": scope,
        "deduplication": "DIRECTION_SELECTION_ONLY_PAIR_IDENTITY_UNVERIFIED",
        "rate_limit_changed": False,
    }

    if metrics.get("accounting_contract") == "soc-direction-accounting:v3":
        result.update(
            contract="soc-packet-accounting:v3",
            rate_budget_unit="RAW_OBSERVATION_AND_ANALYSIS_INDEPENDENT",
            accepted_raw_frames=get("accepted_raw_frames"),
            filtered_raw_frames=get("direction_filtered_frames"),
            outbound_frames=get("outbound_frames"),
            inbound_frames=get("inbound_frames"),
            analysis_accepted=get("analysis_accepted"),
            observation_tokens=metrics.get("observation_tokens"),
            analysis_tokens=metrics.get("analysis_tokens"),
            budget_failure=metrics.get("budget_failure"),
            analysis_rate_limit=get("approved_analysis_packets_per_second"),
            rate_limit_changed=True,
        )
    return result
