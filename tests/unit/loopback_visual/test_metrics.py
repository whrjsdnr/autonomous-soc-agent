"""Accounting cannot reinterpret raw budget; plots cannot confer capture trust."""

import copy

import pytest

from soc_agent.gui.visual_metrics import VisualHistory, record_series
from soc_agent.security_ai.research.packet_accounting import packet_accounting


def snapshot(**net):
    return dict(
        session_id="s",
        input_origin="NATIVE_AF_PACKET",
        collection_live=True,
        state="LIVE_COLLECTION",
        network=net,
    )


def test_accounting_preserves_unknown_direction_and_rejected_frame():
    result = packet_accounting(
        dict(
            received_frames=1217,
            sent_packets=608,
            transport_delivered_packets=608,
            kernel_packets_total=1218,
            capture_drops=0,
            abort_reason="STREAM_RATE_BUDGET_EXCEEDED",
            integrity_scope="CAPTURE_WIDE",
        ),
        origin="NATIVE_AF_PACKET",
    )
    assert result["received_raw_frames"] == 1217
    assert result["kernel_observed_raw_frames"] == 1218
    assert result["normalized_packets_sent"] == result["transport_delivered_packets"] == 608
    assert result["capture_drops"] == 0
    assert result["accepted_raw_frames"] is result["loopback_duplicate_candidates"] is None
    assert result["outbound_frames"] is result["inbound_frames"] is None
    assert result["quality_scope"] == "FAILED_SHARED_CAPTURE_WINDOW"
    assert result["rate_budget_unit"] == "RAW_FRAME_BEFORE_DIRECTION_FILTER"
    assert not result["rate_limit_changed"]


def test_rates_are_distinct_unknown_first_monotonic_intervals_not_lifetime_means():
    history = VisualHistory()
    history.observe(
        snapshot(received_frames=10, sent_packets=5, transport_delivered_packets=3), at=1
    )
    assert history.samples[-1].values["raw"] is None
    history.observe(
        snapshot(
            received_frames=30,
            sent_packets=15,
            transport_delivered_packets=7,
            packets_per_second=999,
        ),
        at=3,
    )
    assert history.samples[-1].values["raw"] == 10
    assert history.samples[-1].values["normalized"] == 5
    assert history.samples[-1].values["delivered"] == 2
    assert history.samples[-1].values["queries"] is None
    assert not history.observe(snapshot(), at=2)
    assert len(history.samples) == 2


@pytest.mark.parametrize("state", ["STOPPED", "ERROR", "DEGRADED", "RETAINED_STREAM_NOT_LIVE"])
def test_no_stopped_or_stale_graph_movement(state):
    history = VisualHistory()
    history.observe(snapshot(received_frames=1), at=1)
    stopped = snapshot(received_frames=10)
    stopped.update(state=state, collection_live=True)
    assert not history.observe(stopped, at=2)
    assert len(history.samples) == 1
    # Resume starts an unknown interval instead of interpolating a gap.
    history.observe(snapshot(received_frames=20), at=3)
    assert history.samples[-1].values["raw"] is None


def test_session_origin_bounds_counter_reset_and_unknowns():
    history = VisualHistory(capacity=2)
    for i in range(4):
        history.observe(snapshot(received_frames=i, capture_drops=0), at=i)
    assert len(history.samples) == 2
    history.observe(snapshot(received_frames=0, capture_drops=True), at=4)
    assert history.samples[-1].values["raw"] is None
    assert history.samples[-1].values["drops"] is None
    changed = snapshot(received_frames=12)
    changed["session_id"] = "different"
    history.observe(changed, at=5)
    assert len(history.samples) == 1 and history.samples[-1].values["raw"] is None
    changed.update(input_origin="FIXTURE", collection_live=False)
    history.observe(changed, at=6)
    assert len(history.samples) == 1


def test_receipts_risk_progress_do_not_fabricate_completion_or_probabilities():
    record = dict(
        receipt=dict(
            profile="quality",
            origin="FIXTURE",
            capture_session="s",
            inferred_at="UTC",
            score=0.99,
            inference_latency_ms=12,
        ),
        investigation=dict(
            status="ASSESSED_READ_ONLY",
            assessment=dict(threat_assessment=dict(severity="info")),
            timeline=dict(
                entries=[
                    dict(
                        content=dict(sequence=2, result=dict(reason="Read-only evidence collected"))
                    )
                ]
            ),
        ),
    )
    data = dict(session_id="s", input_origin="FIXTURE", research=dict(records=[record]))
    assert record_series(data, "severity") == [("UTC", 0.0, "info")]
    assert record_series(data, "progress") == [("UNKNOWN:2", 2.0, "Read-only evidence collected")]
    assert record_series(data, "latency")[0][1] == 12
    withdrawn = copy.deepcopy(data)
    withdrawn["research"]["records"][0]["advisory_current"] = "WITHDRAWN_RESEARCH_ONLY"
    assert record_series(withdrawn, "severity")[0][1] is None
    data["session_id"] = "other"
    assert record_series(data, "quality") == []


def test_cached_backend_publication_does_not_create_zero_rate():
    history = VisualHistory()
    value = snapshot(received_frames=10)
    assert history.observe(value, at=1)
    assert not history.observe(value, at=2)
    assert len(history.samples) == 1
    assert history.samples[-1].values["raw"] is None


def test_native_total_bound_is_not_a_burst_trajectory():
    elapsed, observed = 2.7918953740154393, 1217
    upper_bound = 512 + 256 * elapsed
    assert observed < upper_bound
    # Compatible with an early exhausted short burst; mean is not per-frame timing.
    assert observed / elapsed > 256
    from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget

    bucket = RateBudget(256, 512, 0)
    for _ in range(512):
        bucket.consume(0)
    with pytest.raises(ValueError, match="STREAM_RATE_BUDGET_EXCEEDED"):
        bucket.consume(0)


def test_helper_and_bundle_stay_in_their_original_raw_frame_approval_scope():
    from soc_agent.security_ai.operational.network_capture.calibrated_session import verify_bundle
    from soc_agent.security_ai.research.models import digest

    files = verify_bundle()
    assert (
        files["calibrated_helper.py"]
        == "375c06dbeb4e14c881fa496459182677b4efaa293845ecfac0dab0da663c4703"
    )
    assert digest(files) == "56ec48caac56a248fc0eeb5bb09c4fae4176482ed19ea8c48526f7638ae8bb31"


def test_model_failure_cannot_be_reclassified_as_a_capture_wide_failure():
    result = packet_accounting(
        {"last_error": "ValueError:STREAM_MODEL_OR_INPUT_FAILURE"}, origin="FIXTURE"
    )
    assert result["quality_scope"] == "PREFIX_NOT_COMPLETION"
    unknown = packet_accounting(
        {"abort_reason": "STREAM_INPUT_OR_STORAGE_VALIDATION_FAILED"}, origin="FIXTURE"
    )
    assert unknown["quality_scope"] == "UNKNOWN"
