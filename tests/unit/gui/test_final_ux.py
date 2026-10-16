"""Read-only presentation contracts; no new model/runtime/policy behavior."""

import copy
from datetime import UTC, datetime

import pytest

from soc_agent.gui.insights import (
    measured_receipts,
    model_view,
    number,
    operational,
    stamp,
    status_items,
)
from soc_agent.gui.presentation import screen_data, sections


def snapshot():
    return {
        "runtime_state": "STOPPED",
        "health": "DEGRADED",
        "readiness": "NOT_READY",
        "collector_state": "RESUMED_EXACT",
        "authentication_events": 12,
        "queue_backlog": 0,
        "running_investigations": 0,
        "recent_activity": [{"origin": "NATIVE_OS"}],
        "network": {"state": "STOPPED", "input_origin": "NATIVE_AF_PACKET"},
        "research": {
            "status": "READY",
            "dns": {"status": "READY", "artifact": "VERIFIED"},
            "operational_inference": "BLOCKED",
            "worker_running": False,
            "inference_counts": {"quality": 0, "edge": 0},
            "records": [],
            "model_metrics": {"quality": {"successful": 0, "unknown": 0, "state": "IDLE"}},
        },
    }


def test_retained_native_events_and_research_ready_never_mean_live():
    data = snapshot()
    before = copy.deepcopy(data)
    rows = {key: state for key, state, _ in status_items(data)}
    assert rows["RUNTIME"] == rows["AUTH COLLECTOR"] == rows["NETWORK"] == "STOPPED"
    assert rows["RESEARCH AI"] == "RESEARCH" and rows["OPERATIONAL AI"] == "BLOCKED"
    assert rows["QUEUE BACKLOG"] == "0" and rows["INVESTIGATING"] == "0"
    assert "LIVE" not in rows.values()
    model = model_view(data, "quality")
    assert model["readiness"] == "READY_FOR_OFFLINE_REPLAY" and model["validation"] == "NOT_RUN"
    assert model["count"] == "0" and model["worker"] == "IDLE"
    assert data == before


@pytest.mark.parametrize("value", [None, True, -1, float("nan"), float("inf"), "0"])
def test_unknown_measurements_never_become_zero(value):
    assert number(value) == "UNKNOWN"
    data = snapshot()
    data["queue_backlog"] = value
    assert dict((k, v) for k, v, _ in status_items(data))["QUEUE BACKLOG"] == "UNKNOWN"


@pytest.mark.parametrize("origin", ["FIXTURE", "OFFLINE_PCAP", "UNVERIFIED", None])
def test_running_fixture_collector_is_not_live(origin):
    data = snapshot()
    data["runtime_state"] = "RUNNING"
    data["network"].update(state="RUNNING", input_origin=origin)
    assert dict((k, v) for k, v, _ in status_items(data))["NETWORK"] == "UNKNOWN"


def test_reported_native_capture_and_runtime_errors_are_distinct():
    data = snapshot()
    data.update(runtime_state="RUNNING", health="HEALTHY", readiness="READY")
    data["network"]["state"] = "RUNNING"
    rows = dict((k, v) for k, v, _ in status_items(data))
    assert rows["NETWORK"] == rows["DNS COLLECTOR"] == "LIVE"
    assert rows["AUTH COLLECTOR"] == "READY" and rows["OPERATIONAL AI"] == "BLOCKED"
    data["last_error"] = "LLM_TIMEOUT"
    data["network"]["last_error"] = "PERMISSION_DENIED"
    rows = dict((k, v) for k, v, _ in status_items(data))
    assert rows["RUNTIME"] == rows["NETWORK"] == "ERROR"
    assert rows["AUTH COLLECTOR"] != "READY"


@pytest.mark.parametrize("profile", ["quality", "edge", "dns"])
def test_missing_model_status_is_unknown_and_never_operational_ready(profile):
    model = model_view({}, profile)
    assert model["count"] == model["artifact"] == model["worker"] == "UNKNOWN"
    assert model["validation"] == "UNKNOWN" and model["operational"] == "UNKNOWN"
    assert (
        operational({"research": {"status": "READY", "operational_inference": "READY"}})
        == "UNKNOWN"
    )


def test_worker_indicator_requires_actual_process_for_same_model():
    data = snapshot()
    data["research"]["model_metrics"]["quality"]["state"] = "RUNNING"
    assert model_view(data, "quality")["worker"] == "IDLE"
    data["research"].update(worker_running=True, active_model="dns")
    assert model_view(data, "quality")["worker"] == "UNKNOWN"
    data["research"]["active_model"] = "quality"
    assert model_view(data, "quality")["worker"] == "RUNNING"


def test_history_preserves_measured_zero_and_sorts_actual_time_without_inference():
    data = snapshot()["research"]
    data["records"] = [
        {"receipt": {"profile": "dns", "score": s, "inferred_at": t}}
        for s, t in [(0.0, "2026-10-16T02:00:00Z"), (0.5, "2026-10-16T01:00:00Z")]
    ]
    before = copy.deepcopy(data)
    assert [p["score"] for p in measured_receipts(data)] == [0.5, 0.0]
    assert stamp("2026-10-16T10:00:00+09:00") == "01:00:00 UTC"
    assert stamp(datetime.now(UTC).replace(tzinfo=None).isoformat()) == "UNKNOWN"
    assert data == before
    data["inference_counts"] = None
    assert measured_receipts(data) is None


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -1, 1.1, True])
def test_invalid_model_scores_never_create_chart_points(score):
    assert (
        measured_receipts(
            {
                "inference_counts": {},
                "records": [
                    {
                        "receipt": {
                            "profile": "dns",
                            "inferred_at": "2026-10-16T01:00:00Z",
                            "score": score,
                        }
                    }
                ],
            }
        )
        == []
    )


def test_research_investigation_and_audit_are_projections_not_approval_records():
    record = {
        "key": "key",
        "status": "COMPLETE",
        "receipt": {
            "profile": "dns",
            "origin": "FIXTURE",
            "score": 0.0,
            "artifact_digest": "a" * 64,
            "input_digest": "b" * 64,
            "model_id": "dns-research",
            "inferred_at": "2026-10-16T01:00:00Z",
        },
        "investigation": {
            "status": "ASSESSED_READ_ONLY",
            "incident_id": "c" * 36,
            "action_policy": "WRITE_DENIED",
            "checkpoint_restored": True,
            "context": {"receipt_digest": "d" * 64},
            "evidence_references": ["e" * 64],
        },
    }
    before = copy.deepcopy(record)
    view = {"research_record": record, "research_view": "audit", "audit_integrity": "VERIFIED"}
    result = dict(sections("Network Research", view))
    assert result["Audit integrity"] == "VERIFIED" and result["Model identity"] == "dns-research"
    view["research_view"] = "investigation"
    result = dict(sections("Network Research", view))
    assert "WRITE_DENIED" in result["Recommended action / boundary"]
    assert "not observed fact" in " ".join(result)
    assert record == before


def test_screen_masking_does_not_rewrite_source_or_long_identifiers():
    data = {
        "username": "private-person",
        "path": "/home/private-person/project/model",
        "artifact_digest": "a" * 64,
        "credential": "no-preview",
    }
    result = screen_data(data)
    assert result["path"] == "$HOME/project/model" and result["username"] == "[REDACTED]"
    assert result["artifact_digest"] == "a" * 64
    assert data["username"] == "private-person"


def test_presentation_imports_are_from_the_tested_checkout():
    from pathlib import Path

    from soc_agent.gui import (
        app,
        charts,
        components,
        insights,
        presentation,
        research_view,
        unified,
    )

    checkout = Path(__file__).resolve().parents[3]
    for module in (app, charts, components, insights, presentation, research_view, unified):
        assert Path(module.__file__).resolve().parents[3] == checkout


def test_missing_or_wrong_input_contract_cannot_claim_verified_flow():
    view = {"research_view": "investigation", "research_record": {"key": "unknown"}}
    assert dict(sections("Network Research", view))["Input / validation"] == "UNKNOWN\nUNKNOWN"
    record = view["research_record"]
    record.update(
        status="COMPLETE",
        receipt={
            "contract": "soc-network-research-receipt:v1",
            "origin": "OFFLINE_PCAP",
            "producer_version": "1.1.0",
        },
    )
    assert "OFFLINE_VERIFIED_FLOW" in dict(sections("Network Research", view))["Input / validation"]
    record["receipt"]["origin"] = "NATIVE_AF_PACKET"
    assert "UNKNOWN" in dict(sections("Network Research", view))["Input / validation"]
