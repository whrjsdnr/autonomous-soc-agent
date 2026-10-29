"""Shared dashboard fields retain measured counts and Native/replay provenance."""

from copy import deepcopy

from soc_agent.gui.continuous_projection import project
from soc_agent.gui.production import event_rows
from soc_agent.gui.visual_metrics import VisualHistory


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
