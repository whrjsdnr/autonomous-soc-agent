"""Bound display of existing API results; no API, models, capture or approval issuance."""

from copy import deepcopy

import pytest

from soc_agent.gui import api_attachment


def records():
    task = dict(
        task_id="task1",
        incident_id="incident1",
        evidence_revision="revision1",
        sources=[dict(role="NETWORK", reference="source1", origin="REAL_NATIVE")],
        state="WAITING_HUMAN",
        investigation=dict(llm_mode="SCRIPTED", plan={"steps": []}),
    )
    current = dict(
        source="NATIVE_SERVICE",
        metrics=dict(packets=54, predictions=8),
        cleanup="VERIFIED",
        orchestration=dict(tasks=[task], worker=dict(provider="SCRIPTED")),
    )
    external = deepcopy(task)
    external["investigation"] = dict(
        llm_mode="EXTERNAL_API_ADAPTER_LOCAL_COORDINATION",
        plan=dict(steps=[dict(tool="read_local_source_report", status="completed")]),
        assessment=dict(threat_assessment=dict(severity="info")),
    )
    native = dict(store_id="native-session", configuration=dict(source="NATIVE_SERVICE"))
    retained = dict(
        store_id="api-session",
        snapshot=dict(
            original_capture_session="native-session",
            investigation_input_origin="RETAINED_REAL_NATIVE_NO_NEW_CAPTURE",
            collection_live=False,
            collector="NOT_STARTED",
            api_calls=2,
            cleanup="VERIFIED",
            orchestration=dict(
                tasks=[external],
                worker=dict(api_status=dict(calls=2, total_estimated_usd=None)),
            ),
        ),
    )
    return current, native, retained


def test_same_incident_api_plan_assessment_and_unknown_cost_without_native_mutation(
    tmp_path, monkeypatch
):
    current, native, retained = records()
    before = deepcopy(current)
    api = tmp_path / "api"
    api.mkdir()
    monkeypatch.setattr(
        api_attachment, "observation", lambda path: retained if path == api else native
    )
    result = api_attachment.attach_api_results(tmp_path / "native", api, current)
    assert current == before
    assert result["metrics"] == current["metrics"]
    row = result["orchestration"]["tasks"][0]
    assert row["native_investigation"]["llm_mode"] == "SCRIPTED"
    assert row["investigation"]["assessment"]
    assert row["investigation_result_origin"] == "RETAINED_NATIVE_EXTERNAL_API"
    assert result["api_investigation"]["calls"] == 2
    assert result["api_investigation"]["api_status"]["total_estimated_usd"] is None
    assert result["api_investigation"]["capture_started"] is False


@pytest.mark.parametrize("fault", ["session", "revision", "incident", "source", "provider", "live"])
def test_wrong_api_binding_never_replaces_native_task(tmp_path, monkeypatch, fault):
    current, native, retained = records()
    value = retained["snapshot"]
    row = value["orchestration"]["tasks"][0]
    if fault == "session":
        value["original_capture_session"] = "another-session"
    elif fault == "live":
        value["collection_live"] = True
    elif fault == "provider":
        row["investigation"]["llm_mode"] = "SCRIPTED"
    else:
        row[
            {"revision": "evidence_revision", "incident": "incident_id", "source": "sources"}[fault]
        ] = [] if fault == "source" else "changed"
    api = tmp_path / "api"
    api.mkdir()
    monkeypatch.setattr(
        api_attachment, "observation", lambda path: retained if path == api else native
    )
    with pytest.raises(ValueError, match="MISMATCH"):
        api_attachment.attach_api_results(tmp_path / "native", api, current)
    assert current["orchestration"]["tasks"][0]["investigation"]["llm_mode"] == "SCRIPTED"


def test_waiting_api_is_expected_without_starting_it(tmp_path, monkeypatch):
    current, native, _ = records()
    monkeypatch.setattr(api_attachment, "observation", lambda _: native)
    result = api_attachment.attach_api_results(tmp_path / "native", tmp_path / "absent", current)
    assert result["api_investigation"] == dict(status="WAITING_AUTHORIZED_API_RESULT", calls=0)
    assert not (tmp_path / "absent").exists()
