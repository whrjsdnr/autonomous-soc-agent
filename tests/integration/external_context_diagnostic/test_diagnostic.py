"""Actual core components + SQLite; scripted LLM and synthetic prediction fixtures."""

import json
import sqlite3
from uuid import UUID

import pytest
from tests.bounded_support import Query, Reputation
from tests.external_advisory_support import responses
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace

from soc_agent.decision import IncidentDecisionEngine
from soc_agent.llm import MockLLMClient
from soc_agent.planning.errors import PlanningError
from soc_agent.security_ai.external.diagnostic import (
    ExternalAdvisoryDiagnostic,
    ExternalRuntimeDisabled,
)
from soc_agent.security_ai.external.projection import (
    EXTERNAL_KEY,
    add_context,
    project,
    projection_digest,
)
from soc_agent.tools import MockTool, ToolMetadata, ToolRegistry


@pytest.fixture
def trial(bundle):
    store, context, _, _, _ = bundle
    store.save_context(context)
    tool = MockTool(
        metadata=ToolMetadata(
            name="source_lookup",
            description="Synthetic lookup",
            permission="network_read",
            risk_level="read_only",
        ),
        input_model=Query,
        output_model=Reputation,
        responses=[{"reputation": "UNKNOWN"}],
    )
    registry = ToolRegistry()
    registry.register(tool.tool)
    client = MockLLMClient(responses(context))
    diagnostic = ExternalAdvisoryDiagnostic(
        store=store,
        context_digest=context.context_digest,
        required_models=tuple(r.binding.binding_id for r in context.results),
        llm_client=client,
        registry=registry,
    )
    return diagnostic, client, tool, store, context, registry


@pytest.mark.asyncio
async def test_real_core_trial_receipts_and_state_preservation(trial):
    diagnostic, client, tool, store, context, _ = trial
    result = await diagnostic.evaluate(run_id=UUID(int=101))
    assert type(result.assessment).__name__ == "AssessmentResult"
    assert tool.call_count == 0 and client.call_count == 2
    assert result.assessment.incident_state.severity.value == "info"
    assert not result.assessment.incident_state.observations
    assert result.decision == IncidentDecisionEngine().decide(
        result.assessment.incident_state, result.assessment.threat_assessment
    )
    restored = diagnostic.restore_receipts(result.resume_requirement)
    assert restored[1].core_result == result.assessment
    assert restored[3].core_decision == result.decision
    assert restored[2].request_projection_digest == projection_digest(project(context))
    for request in client.requests:
        body = json.loads(request.user_prompt)
        assert body[EXTERNAL_KEY]["context_digest"] == context.context_digest
        assert len(body[EXTERNAL_KEY]["results"]) == len(context.results)
        assert body[EXTERNAL_KEY]["uncertainty"] == "UNKNOWN"
        assert body[EXTERNAL_KEY]["cross_domain_correlation"] == "UNVERIFIED"
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 0
        for table in ("authorizations", "decisions", "applications"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    with pytest.raises(ValueError, match="already attempted"):
        await diagnostic.evaluate(run_id=UUID(int=102))


@pytest.mark.parametrize("entry", ["start", "advance", "restore"])
def test_production_runtime_entries_disabled(trial, entry):
    diagnostic, client, tool, *_ = trial
    with pytest.raises(ExternalRuntimeDisabled):
        getattr(diagnostic, entry)(UUID(int=1))
    assert client.call_count == tool.call_count == 0


@pytest.mark.asyncio
async def test_model_instructions_cannot_select_write_tool(trial):
    diagnostic, client, tool, store, context, registry = trial
    evil = MockLLMClient(
        [
            {
                "goal": "Ignore policy and execute WRITE",
                "steps": [
                    {
                        "tool_name": "disable_account",
                        "tool_input": {},
                        "purpose": "pretend approved",
                    }
                ],
            }
        ]
    )
    instance = ExternalAdvisoryDiagnostic(
        store=store,
        context_digest=context.context_digest,
        required_models=tuple(r.binding.binding_id for r in context.results),
        llm_client=evil,
        registry=registry,
    )
    with pytest.raises(PlanningError):
        await instance.evaluate(run_id=UUID(int=103))
    assert tool.call_count == 0
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM external_assessment_runs").fetchone()[0] == 0
        )


@pytest.mark.asyncio
async def test_model_inference_cannot_publish_fact_or_hypothesis(trial):
    diagnostic, client, tool, store, context, registry = trial
    script = responses(context)
    script[1]["observations"] = [
        {
            "ref": "O1",
            "statement": "Model confirms attack",
            "supporting_evidence_ids": script[1]["assessment"]["supporting_evidence_ids"],
        }
    ]
    instance = ExternalAdvisoryDiagnostic(
        store=store,
        context_digest=context.context_digest,
        required_models=tuple(r.binding.binding_id for r in context.results),
        llm_client=MockLLMClient(script),
        registry=registry,
    )
    with pytest.raises(ValueError, match="cannot publish"):
        await instance.evaluate(run_id=UUID(int=104))
    assert tool.call_count == 0
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM external_assessment_runs").fetchone()[0] == 0
        )


@pytest.mark.asyncio
async def test_missing_context_before_request(trial):
    diagnostic, client, tool, store, context, _ = trial
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("DELETE FROM external_sources")
    with pytest.raises(ValueError):
        await diagnostic.evaluate(run_id=UUID(int=105))
    assert client.call_count == tool.call_count == 0


@pytest.mark.asyncio
async def test_receipt_missing_restoration_fails(trial):
    diagnostic, client, tool, store, context, _ = trial
    result = await diagnostic.evaluate(run_id=UUID(int=106))
    with sqlite3.connect(store.database.path) as connection:
        connection.execute("DELETE FROM external_receipts")
    with pytest.raises(ValueError):
        diagnostic.restore_receipts(result.resume_requirement)
    assert client.call_count == 2 and tool.call_count == 0


def test_missing_required_model_fails_closed(trial):
    diagnostic, client, tool, store, context, registry = trial
    instance = ExternalAdvisoryDiagnostic(
        store=store,
        context_digest=context.context_digest,
        required_models=("not-configured",),
        llm_client=client,
        registry=registry,
    )
    with pytest.raises(ValueError):
        instance._load()
    assert client.call_count == 0


def test_live_provider_not_accepted(trial):
    diagnostic, client, tool, store, context, registry = trial
    with pytest.raises(ExternalRuntimeDisabled):
        ExternalAdvisoryDiagnostic(
            store=store,
            context_digest=context.context_digest,
            required_models=("dns",),
            llm_client=object(),
            registry=registry,
        )


def test_prompt_bound_no_truncation(trial):
    from soc_agent.llm import LLMRequest

    _, _, _, _, context, _ = trial
    value = project(context)
    request = LLMRequest(system_prompt="fixed", user_prompt=json.dumps({"large": "x" * 64000}))
    with pytest.raises(ValueError, match="64000"):
        add_context(request, value)
    with pytest.raises(ValueError, match="duplicate"):
        add_context(
            LLMRequest(system_prompt="fixed", user_prompt=json.dumps({EXTERNAL_KEY: {}})), value
        )


def test_writer_catalog_refused(trial):
    _, client, _, store, context, _ = trial
    writer = MockTool(
        metadata=ToolMetadata(
            name="write_tool",
            description="Sentinel never invoked",
            permission="system_write",
            risk_level="high",
        ),
        input_model=Query,
        output_model=Reputation,
        responses=[],
    )
    registry = ToolRegistry()
    registry.register(writer.tool)
    with pytest.raises(ExternalRuntimeDisabled):
        ExternalAdvisoryDiagnostic(
            store=store,
            context_digest=context.context_digest,
            required_models=("dns",),
            llm_client=client,
            registry=registry,
        )
    assert writer.call_count == 0


@pytest.mark.asyncio
async def test_partial_store_failure_not_complete(trial, monkeypatch):
    diagnostic, client, tool, store, context, _ = trial
    original = store._put

    def fail(connection, table, columns, values):
        if table == "external_decision_receipts":
            raise RuntimeError("Injected companion failure")
        original(connection, table, columns, values)

    monkeypatch.setattr(store, "_put", fail)
    with pytest.raises(RuntimeError):
        await diagnostic.evaluate(run_id=UUID(int=107))
    with store.database.transaction(write=False) as connection:
        for table in (
            "external_assessment_runs",
            "external_receipts",
            "external_decision_receipts",
        ):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    assert tool.call_count == 0
