"""Existing HTTP adapter and SOCRuntime, with fake transport; no live API/model."""

import json

import pytest

from soc_agent.continuous.api_investigation import RetainedAPIClient, retained_input
from soc_agent.continuous.investigation import application
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.llm import LLMRequest
from soc_agent.llm.openai_compatible import OpenAICompatibleClient
from soc_agent.security_ai.api_investigation import APIInvestigationClient, minimized
from soc_agent.security_ai.research.models import digest
from tests.integration.test_api_investigation import authorization, response, settings
from tests.integration.test_continuous_orchestration import drained, source
from tests.unit.continuous.test_runtime import make


def setup_client(tmp_path):
    _, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    item = source(
        advisory=dict(
            agreement_state="conflicting",
            raw_payload="SECRET_PAYLOAD_MUST_STAY_LOCAL",
            model_results=[
                dict(prediction="CLASS_1", artifact_digest="a" * 64, feature_fingerprint="b" * 64)
            ],
        )
    )
    task = tasks.submit(item)
    a = authorization(tmp_path / "api", b"unused").model_copy(
        update={"input_sha256": digest(retained_input(task, [item]))}
    )
    records = {}

    def write(name, value):
        assert name not in records  # Same adapter may not replay an old receipt.
        records[name] = value

    api = APIInvestigationClient(a, settings(a), write, store.event)
    return tasks, task, item, api, records


@pytest.mark.asyncio
async def test_existing_api_adapter_reaches_core_plan_tool_assessment_and_gui(
    tmp_path, monkeypatch
):
    tasks, task, item, api, records = setup_client(tmp_path)
    calls = []

    def post(self, body):
        request = json.loads(body)
        prompt = json.loads(request["messages"][1]["content"])
        calls.append(prompt)
        assert "SECRET_PAYLOAD_MUST_STAY_LOCAL" not in body.decode()
        if "AVAILABLE READ-ONLY TOOLS" in prompt:
            assert prompt["OBSERVED EVIDENCE (UNTRUSTED SOURCE DATA)"]
            assert (
                prompt["CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)"][0]["agreement_state"]
                == "conflicting"
            )
            draft = dict(
                decision="continue_with_tool",
                reason="TEST TRANSPORT: inspect conflicting retained predictions",
                tool=dict(
                    tool_name="read_local_source_report",
                    tool_input=dict(incident_id=str(task.incident_id)),
                    purpose="Check retained provenance",
                ),
            )
        else:
            draft = response(request)
        return json.dumps(
            dict(
                choices=[dict(finish_reason="stop", message=dict(content=json.dumps(draft)))],
                usage=dict(prompt_tokens=400, completion_tokens=300),
            )
        ).encode()

    monkeypatch.setattr(OpenAICompatibleClient, "_post", post)
    client = RetainedAPIClient(api, task, [item])
    await drained(tasks, client)
    snapshot = tasks.snapshot()["tasks"][0]
    assert snapshot["state"] == "WAITING_HUMAN"
    assert snapshot["waiting_reason"] == "Planner requires independent human review"
    assert snapshot["investigation"]["assessment"]
    assert snapshot["investigation"]["llm_mode"] == client.evidence_mode
    assert api.calls == len(calls) == len(api.receipts) == 2
    checkpoint = application(tasks, task, client).checkpoint(task.incident_id)
    assert checkpoint.artifacts.investigation.steps[0].status.value == "completed"
    assert checkpoint.artifacts.execution_intent_id is None
    assert len([name for name in records if name.startswith("api-response-")]) == 2
    assert "TEST_SECRET" not in json.dumps(records)
    await drained(tasks, client)
    assert len(calls) == 2


def test_api_binding_rejects_changed_source_or_revision(tmp_path):
    _, task, item, api, _ = setup_client(tmp_path)
    changed = item.model_copy(update={"advisory": {"agreement_state": "consistent"}})
    with pytest.raises(ValueError, match="REVISION_MISMATCH"):
        RetainedAPIClient(api, task, [changed])
    api.authorization = api.authorization.model_copy(update={"input_sha256": "f" * 64})
    with pytest.raises(ValueError, match="AUTHORIZATION_INPUT_MISMATCH"):
        RetainedAPIClient(api, task, [item])


@pytest.mark.asyncio
async def test_changed_context_cannot_reach_provider(tmp_path):
    _, task, item, api, _ = setup_client(tmp_path)
    client = RetainedAPIClient(api, task, [item])
    from soc_agent.assessment.models import SecurityAnalysisDraft

    with pytest.raises(ValueError, match="CONTEXT_CHANGED"):
        await client.generate_structured(
            request=LLMRequest(system_prompt="test", user_prompt="{}"),
            response_model=SecurityAnalysisDraft,
        )
    assert api.calls == 0


def test_adaptive_history_keeps_status_but_withholds_untrusted_text():
    from uuid import uuid4

    request = LLMRequest(
        system_prompt="test",
        user_prompt=json.dumps(
            {
                "AVAILABLE READ-ONLY TOOLS": [{"name": "read_local_source_report"}],
                "TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)": [
                    dict(
                        step_id=str(uuid4()),
                        tool_name="read_local_source_report",
                        status="completed",
                        purpose="PRIVATE_LOG_CONTENT",
                    )
                ],
                "AVAILABLE SECURITY AI": [{"name": "UNAPPROVED_MODEL"}],
            }
        ),
    )
    result = minimized(request)
    assert "PRIVATE_LOG_CONTENT" not in result.user_prompt
    assert "UNAPPROVED_MODEL" not in result.user_prompt
    body = json.loads(result.user_prompt)
    assert body["TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)"][0]["status"] == "completed"
    assert body["AVAILABLE SECURITY AI"] == []


@pytest.mark.asyncio
async def test_assessment_timeout_keeps_plan_cost_uncertainty_checkpoint_and_gui(
    tmp_path, monkeypatch
):
    import asyncio

    from soc_agent.gui.backend import Backend, GUIConfig
    from soc_agent.llm import LLMTimeoutError

    tasks, task, item, api, records = setup_client(tmp_path)
    original = OpenAICompatibleClient.generate_structured
    seen = []

    def post(self, body):
        prompt = json.loads(json.loads(body)["messages"][1]["content"])
        assert "AVAILABLE READ-ONLY TOOLS" in prompt
        draft = dict(
            decision="continue_with_tool",
            reason="FAKE_HTTP inspect retained data",
            tool=dict(
                tool_name="read_local_source_report",
                tool_input=dict(incident_id=str(task.incident_id)),
                purpose="Check retained provenance",
            ),
        )
        return json.dumps(
            dict(
                choices=[dict(finish_reason="stop", message=dict(content=json.dumps(draft)))],
                usage=dict(prompt_tokens=400, completion_tokens=300),
            )
        ).encode()

    async def generate(self, *, request, response_model):
        seen.append(response_model.__name__)
        if response_model.__name__ == "SecurityAnalysisDraft":
            # Exercise actual outer API adapter and core checkpoint. No HTTP here.
            self.last_usage = None
            await asyncio.sleep(0.01)
            raise LLMTimeoutError("FAKE_HTTP approved assessment deadline")
        return await original(self, request=request, response_model=response_model)

    monkeypatch.setattr(OpenAICompatibleClient, "_post", post)
    monkeypatch.setattr(OpenAICompatibleClient, "generate_structured", generate)
    client = RetainedAPIClient(api, task, [item])
    await drained(tasks, client)
    row = tasks.snapshot()["tasks"][0]
    assert row["state"] == "FAILED"
    assert row["investigation"]["plan"]["steps"][0]["status"] == "completed"
    assert row["investigation"]["assessment"] is None
    cost = row["investigation"]["api_status"]
    assert cost["calls"] == 2 and cost["stopped"]
    assert cost["billing_outcome"] == "UNKNOWN_REQUIRES_REVIEW"
    assert cost["total_estimated_usd"] is None
    assert cost["confirmed_response_estimate_usd"] == "0.001"
    assert [r["operation"] for r in cost["requests"]] == ["PLAN", "ASSESSMENT"]
    assert cost["requests"][1]["error_type"] == "LLMTimeoutError"
    failure = records["api-failure-1.json"]
    assert failure["latency_ms"] > 0 and failure["usage"] is None
    assert failure["remote_outcome"] == "UNKNOWN_NO_AUTOMATIC_RESUME"
    assert records["api-response-0.json"]["status"] == "SCHEMA_VALIDATED"
    assert (
        application(tasks, task, client).checkpoint(task.incident_id).artifacts.assessment is None
    )
    await drained(tasks, client)
    assert len(seen) == 2  # Resume never duplicates plan/tool or uncertain API request.
    tasks.service.update(
        dict(state="STOPPED", source="JSONL_REPLAY", orchestration=tasks.snapshot())
    )
    backend = Backend(
        GUIConfig(data_directory=tmp_path / "gui", continuous_directory=tasks.service.directory)
    )
    try:
        view = (await backend.investigations())[0]
        assert view["task_id"] == str(task.task_id)
        assert view["investigation"]["api_status"] == cost
        assert view["investigation"]["assessment"] is None
    finally:
        await backend.close()
