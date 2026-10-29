"""FIXTURE seal, real RF/LR and SCRIPTED planner. No Native or API execution."""

import json

import pytest

from soc_agent.continuous.capture import sealed_jobs
from soc_agent.desktop import OfflineDesktopClient
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
    workflow = OfflineWorkflow(tmp_path / "run", paths=research_paths())
    result = await workflow.run(job)
    assert len(result.inference) == len(calls) == 2
    assert result.investigation["status"] == "COMPLETED_READ_ONLY"
    assert result.external_provider_calls == 0
    assert verify_result(workflow.directory) == result
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
