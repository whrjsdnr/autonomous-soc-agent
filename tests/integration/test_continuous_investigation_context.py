"""FIXTURE seal, real RF/LR and SCRIPTED planner. No Native or API execution."""

import json

import pytest

from soc_agent.continuous.capture import sealed_jobs
from soc_agent.desktop import OfflineDesktopClient
from soc_agent.gui.analysis_service import project_result
from soc_agent.gui.continuous_projection import project
from soc_agent.gui.result_views import ResultViews
from soc_agent.gui.visual_metrics import record_series
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.models import digest
from tests.research_adapter_support import research_paths
from tests.unit.continuous.test_capture_admission import transcript


@pytest.mark.asyncio
async def test_incident_window_flow_context_reaches_plan_and_assessment(tmp_path, monkeypatch):
    calls = []
    original = OfflineDesktopClient.generate_structured

    async def recorded(self, *, request, response_model):
        calls.append(json.loads(request.user_prompt))
        return await original(self, request=request, response_model=response_model)

    monkeypatch.setattr(OfflineDesktopClient, "generate_structured", recorded)

    job = sealed_jobs(*transcript(), origin="FIXTURE")[0][0]
    workflow = OfflineWorkflow(tmp_path / "analysis/run", paths=research_paths())
    result = await workflow.run(job)
    assert len(result.inference) == len(calls) == 2
    assert result.investigation["status"] == "COMPLETED_READ_ONLY"
    assert result.external_provider_calls == 0
    assert verify_result(workflow.directory) == result
    compact = dict(
        incident_id=str(result.incident_id),
        origins=["FIXTURE"],
        output=str(workflow.directory),
        predictions=[],
    )
    views = ResultViews()
    enriched = views.enrich(tmp_path, dict(recent_results=[compact]))
    assert enriched["recent_results"][0]["report_view"] == "VERIFIED_REPORT_AND_AUDIT"
    shown = project(dict(continuous=enriched | dict(source="FIXTURE")))
    shown["input_origin"] = "FIXTURE"
    summary = project_result(result)
    assert [p[1] for p in record_series(shown, "latency")] == [
        p["inference_latency_ms"] for p in summary["predictions"]
    ]
    assert all(p[0] != "UNKNOWN" for p in record_series(shown, "latency"))
    assert [p[1] for p in record_series(shown, "severity")] == [0, 0]
    assert record_series(shown, "progress")[0][1] == 1
    assert shown["research"]["records"][0]["investigation"]["llm_mode"] == "SCRIPTED"
    for prompt in calls:
        context = prompt["MODEL ANALYSIS (UNTRUSTED ADVISORY, NOT OBSERVED FACTS)"]
        assert context["incident_id"] == str(result.incident_id)
        identity = context["input_identity"]
        assert identity["job_digest"] == digest(job.model_dump(mode="json"))
        assert identity["origins"] == ["FIXTURE"]
        assert identity["sessions"] == [str(job.session)]
        assert identity["namespaces"] == [job.namespace]
        assert identity["capture_window_ids"] == [
            job.result["tcx"]["data_plane"]["continuous_window"]["id"]
        ]
        assert identity["flow_ids"] == sorted({r.event_identity for r in result.inference})
        assert "source_address" not in json.dumps(identity)
    assert result.response["host_remediation"] is False
    context_file = workflow.directory / "investigation-context.json"
    raw = json.loads(context_file.read_text())
    raw["input_identity"]["flow_ids"] = []
    context_file.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="CONTEXT_AUDIT_MISMATCH"):
        verify_result(workflow.directory)
    invalid = views.enrich(tmp_path, dict(recent_results=[compact]))
    assert invalid["recent_results"][0]["report_view"] == "UNVERIFIED"
    assert invalid["recent_results"][0]["predictions"] == []
