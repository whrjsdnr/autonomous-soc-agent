"""Explicit native-only checks: configured artifact root/native Python; no LLM provider."""

import os
from pathlib import Path

import pytest

from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.llm import MockLLMClient
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.security_ai.external.service import ModelInput
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry
from tests.bounded_support import Query, Reputation
from tests.external_advisory_support import responses
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace


@pytest.mark.asyncio
async def test_native_runtime_status_and_recorded_validation(bundle, workspace):
    _, template, *_ = bundle
    artifact = Path(os.environ["SOC_EXTERNAL_ARTIFACT_ROOT"])
    interpreter = Path(os.environ["SOC_EXTERNAL_INFERENCE_PYTHON"])
    store = RuntimeGovernanceStore.activate_validation_workspace(workspace)
    calls = []

    async def read(value):
        calls.append(value)
        return Reputation(reputation="UNKNOWN")

    registry = ToolRegistry()
    registry.register(
        Tool(
            metadata=ToolMetadata(
                name="source_lookup",
                description="Synthetic READ",
                permission="network_read",
                risk_level="read_only",
            ),
            input_model=Query,
            output_model=Reputation,
            handler=read,
        )
    )
    plan, assessment = responses(template)
    app = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="SERVER"),
        registry=registry,
        llm_client=MockLLMClient([assessment, plan, assessment, plan]),
        external_artifacts=artifact,
        external_interpreter=interpreter,
    )
    incident = template.input_snapshot.incident_id
    context = app.service.analyze_external(
        incident,
        tuple(ModelInput(binding=r.binding, observation=r.observation) for r in template.results),
    )
    runtime = app.service.runtime_factory()
    runtime.start(incident)
    for _ in range(12):
        result = await runtime.advance(incident)
        if result.waiting_for_human or result.terminal:
            break
    assert result.waiting_for_human and len(calls) == 1
    with store.database.transaction(write=False) as c:
        before = tuple(c.iterdump())
    status = app.service.security_ai_status(incident_id=incident)
    assert status.environment_scope == "CONFIGURED_NATIVE_INTERPRETER"
    assert all(
        p.artifact == "VERIFIED" and p.backend_dependencies == "VERIFIED" for p in status.packages
    )
    assert all(
        p.demo_inference == "UNKNOWN" and p.operational_input == "NOT_INFERABLE"
        for p in status.packages
    )
    assert status.last_validation.context_digest == context.context_digest
    assert status.last_validation.environment_digests
    assert status.last_validation_check == "RECORDED"
    assert not status.last_validation.native_inference_this_query
    assert (
        str(artifact) not in status.model_dump_json()
        and str(interpreter) not in status.model_dump_json()
    )
    with store.database.transaction(write=False) as c:
        assert tuple(c.iterdump()) == before
    restored = app.service.runtime_factory()
    assert restored.restore(incident) == runtime.checkpoint(incident).result
    after = app.service.security_ai_status(incident_id=incident)
    assert after.last_validation == status.last_validation
    assert after.write_disposition == "WRITE_DENIED"
