"""Existing actual pinned external artifacts -> product service -> actual SOCRuntime."""

import os
from pathlib import Path

import pytest
from tests.bounded_support import Query, Reputation
from tests.external_advisory_support import responses
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace

from soc_agent.application import compose_application
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.llm import MockLLMClient
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.security_ai.external.service import ModelInput
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry


@pytest.mark.asyncio
async def test_actual_native_service_runtime_context_and_restart(bundle, workspace):
    _, template, *_ = bundle
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
                description="Synthetic read",
                permission="network_read",
                risk_level="read_only",
            ),
            input_model=Query,
            output_model=Reputation,
            handler=read,
        )
    )
    plan, assessment = responses(template)
    client = MockLLMClient([assessment, plan, assessment, plan])
    artifact = Path(
        os.environ.get("SOC_EXTERNAL_ARTIFACT_ROOT", "/tmp/soc-gate-b-artifacts-20261012")
    )
    interpreter = Path(
        os.environ.get(
            "SOC_EXTERNAL_INFERENCE_PYTHON", "/tmp/security-ai-artifact-validation/bin/python"
        )
    )
    assert artifact.is_dir() and interpreter.is_file(), (
        "Explicit native validation environment unavailable"
    )
    application = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="SERVER"),
        registry=registry,
        llm_client=client,
        external_artifacts=artifact,
        external_interpreter=interpreter,
    )
    incident = template.input_snapshot.incident_id
    inputs = tuple(
        ModelInput(binding=r.binding, observation=r.observation) for r in template.results
    )
    context = application.service.analyze_external(incident, inputs)
    assert context.results and all(
        r.provenance.execution_environment_digest for r in context.results
    )
    assert len(context.results) == len(inputs)
    assert len(context.correlation_groups) == 1
    runtime = application.service.runtime_factory()
    runtime.start(incident)
    for _ in range(12):
        result = await runtime.advance(incident)
        if result.waiting_for_human or result.terminal:
            break
    assert result.waiting_for_human and not result.terminal
    assert len(calls) == 1
    assert runtime.artifacts(incident).decision is not None
    restored = application.service.runtime_factory()
    assert restored.restore(incident) == runtime.checkpoint(incident).result
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM external_decision_receipts").fetchone()[0] > 0
        )
