"""Shared dashboard fields retain measured counts and Native/replay provenance."""

from copy import deepcopy

from soc_agent.gui.continuous_projection import project
from soc_agent.gui.production import event_rows
from soc_agent.gui.visual_metrics import VisualHistory, record_series


def current():
    return dict(
        source="NATIVE_SERVICE",
        state="RUNNING",
        collector="RUNNING",
        worker="IDLE",
        collection_live=True,
        clock_epoch="runtime-epoch",
        heartbeat_unix=10,
        uptime_seconds=1,
        metrics=dict(
            packets=20, native_events=20, predictions=0, queue_dropped=0, eligible=1, incomplete=1
        ),
        queue={"PENDING": 1},
        capture_window=dict(assessment=dict(status="VERIFIED")),
        last_error=None,
    )


def test_dashboard_uses_attached_runtime_not_stopped_legacy_state():
    original = dict(state="STOPPED", input_origin="NO_DATA", continuous=current())
    before = deepcopy(original)
    shown = project(original)
    assert shown["state"] == shown["collectors"]["network"] == "RUNNING"
    assert shown["input_origin"] == "REAL_NATIVE" and shown["collection_live"]
    assert shown["network"]["queue_backlog"] == 1
    assert shown["network"]["packets_collected"] == 20
    assert "received_raw_frames" not in shown["network"]["packet_accounting"]
    assert original == before  # projection never mutates audit/backend evidence


def test_native_rate_graph_requires_real_counter_delta_and_live_state():
    body = current()
    history = VisualHistory()
    history.observe(project(dict(continuous=body)), at=1)
    body = body | dict(
        uptime_seconds=3, metrics=body["metrics"] | dict(packets=40, native_events=40)
    )
    assert history.observe(project(dict(continuous=body)), at=3)
    assert history.samples[-1].values["delivered"] == 10
    count = len(history.samples)
    assert not history.observe(
        project(dict(continuous=body | dict(state="STOPPED", collection_live=False))), at=4
    )
    assert len(history.samples) == count


def test_retained_model_selection_does_not_increment_live_predictions():
    body = current() | dict(state="STOPPED", collection_live=False)
    result = dict(
        audit="VERIFIED",
        incident_id="incident-1",
        classification="UNKNOWN_ANOMALY",
        input_origins=["REAL_NATIVE"],
        investigation_status="COMPLETED_READ_ONLY",
        predictions=[
            dict(model="linux-network14-research-v1-quality_rf", prediction="anomaly", score=0.5)
        ],
    )
    shown = project(dict(continuous=body, analysis=dict(result=result, output="/retained/output")))
    assert shown["network"]["inference_count"] == 0 and not shown["collection_live"]
    assert shown["research"]["model_metrics"]["quality"]["successful"] == 1
    rows = event_rows(shown)
    assert len(rows) == 1 and rows[0][1]["analysis_output"] == "/retained/output"
    assert rows[0][1]["receipt"]["contract"] == "soc-gui-continuous-prediction-view:v1"


def test_legacy_dashboard_is_unchanged_without_attachment():
    value = dict(state="LIVE_COLLECTION", research=dict(records=[]))
    assert project(value) is value


def test_capture_quality_uses_sealed_counter_evidence_not_queue_or_system_wide_loss():
    body = current()
    body["metrics"] |= dict(queue_dropped=7, source_gaps=2)
    body["producer"] = dict(generation=11)
    body["capture_window"] = dict(
        id="window-10",
        assessment=dict(
            status="INCOMPLETE",
            same_epoch=True,
            counter_reconciliation="RECONCILED",
            window_evidence=dict(
                clock=dict(status="VERIFIED", epoch=10),
                cpus=[
                    dict(cpu=0, counters=dict(ring_reservation_failures=0)),
                    dict(cpu=1, counters=dict(ring_reservation_failures=1)),
                ],
            ),
        ),
    )
    shown = project(dict(continuous=body))
    quality = shown["capture_quality"]
    assert quality["window_id"] == "window-10"
    assert quality["active_generation"] == 11 and quality["sealed_generation"] == 10
    assert quality["kernel_wide_drops"] == "UNKNOWN" and quality["owned_ring_loss"] == 1
    assert quality["queue_drops"] == 7
    assert shown["network"]["capture_drops"] == 1 and shown["network"]["gap_count"] == 2
    history = VisualHistory()
    history.observe(shown, at=1)
    assert history.samples[-1].values["drops"] == 1


def test_missing_sealed_counter_is_not_reported_as_zero_loss():
    shown = project(dict(continuous=current()))
    assert shown["capture_quality"]["owned_ring_loss"] is None
    assert shown["network"]["capture_drops"] is None


def test_authentication_scope_and_collection_state_are_not_borrowed_from_network():
    body = current() | dict(
        authentication=dict(state="NOT_ATTACHED", events=None),
        authentication_transport=dict(state="NOT_ATTACHED", source=None),
    )
    shown = project(dict(continuous=body))
    assert shown["authentication"]["runtime_state"] == "NOT_ATTACHED"
    assert shown["authentication"]["input_origin"] == "NO_DATA"
    assert "NOT_IN_TCP_TRIAL_SCOPE" in shown["authentication"]["reason"]


def test_offline_pcap_latency_is_visible_without_native_promotion():
    body = current() | dict(
        source="PCAP_REPLAY",
        recent_results=[
            dict(
                incident_id="offline-incident",
                origins=["OFFLINE_PCAP"],
                predictions=[
                    dict(
                        model="linux-network14-research-v1-quality_rf",
                        prediction="CLASS_0",
                        inference_latency_ms=12.5,
                        inferred_at="recorded-time",
                    )
                ],
            )
        ],
    )
    shown = project(dict(continuous=body))
    assert shown["input_origin"] == "OFFLINE_PCAP"
    assert record_series(shown, "latency") == [("recorded-time", 12.5, "quality · OFFLINE_PCAP")]


def test_historical_timeout_is_visible_without_rewriting_the_original():
    body = current() | dict(state="STOPPED", last_error="TimeoutError:")
    shown = project(dict(continuous=body))
    assert shown["last_error"] == "CONTINUOUS_SOURCE_TIMEOUT"
    assert shown["continuous"]["last_error"] == "TimeoutError:"


def test_native_empty_charts_explain_action_gate_and_keep_dns_counters_separate():
    from soc_agent.gui.continuous_projection import measurement_reason
    from soc_agent.gui.production import safe_error

    body = current() | dict(
        state="DEGRADED",
        last_error="CaptureUnavailable:HELPER_HEARTBEAT_OR_PROCESS_STALE",
        native_model="EXACT_RETAINED_WINDOW_ACTION_APPROVAL_REQUIRED",
        dns=dict(
            counts={"QUERY": 3, "MATCHED_RESPONSE": 3, "TRANSPORT_CONTROL": 8},
            diagnostic_status="HEALTHY",
        ),
        dns_transport=dict(
            state="FAILED",
            origin="REAL_NATIVE_DNS_METADATA",
            listener_ready=False,
            dns_parse_failures=8,
        ),
        cleanup="UNVERIFIED",
    )
    original = deepcopy(body)
    shown = project(dict(continuous=body))
    assert body == original
    state = shown["runtime_observability"]
    assert state["inference"] == "BLOCKED_SEALED_JOB_ACTION_APPROVAL"
    assert state["investigation"] == "NO_INCIDENT_NO_INVESTIGATION_RESULT"
    assert measurement_reason(shown, "latency") == state["inference"]
    assert measurement_reason(shown, "severity") == "NO_INCIDENT_NO_RESEARCH_ASSESSMENT"
    assert state["dns"]["transactions"] == 3 and state["dns"]["raw_helper_parse_failures"] == 8
    assert state["dns"]["semantic_parse_failures"] == 0
    assert state["dns"]["helper_authenticated"] and state["dns"]["transport_control"] == 8
    assert shown["research"]["model_metrics"]["quality"]["successful"] == 0
    assert safe_error(shown["last_error"]) == "HELPER_HEARTBEAT_OR_PROCESS_STALE"
    assert safe_error("CaptureUnavailable:secret=never show") == "UNKNOWN"
    assert state["cleanup"] == "UNVERIFIED"
