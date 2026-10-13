"""Deployment metadata cannot change shared runtime or governance behavior."""

import ast
import asyncio
from pathlib import Path

import pytest
from pydantic import ValidationError

from soc_agent.api.models import StepRequest
from soc_agent.application import compose_application, open_application_store
from soc_agent.demo.composition import DemoLLM
from soc_agent.demo.model_analysis import PackagedAnalysis as CompatibleAnalysis
from soc_agent.demo.scenarios import scenario_event
from soc_agent.demo.tools import demo_network_tool, demo_read_tool, demo_response_tool
from soc_agent.deployment import DeploymentDescriptor, DeploymentProfile
from soc_agent.ingestion import EventIngestor, migrate_ingestion
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.llm.openai_compatible import OpenAICompatibleClient
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.security_ai.model_analysis import PackagedAnalysis
from soc_agent.security_ai.packaging import load_package
from soc_agent.tools import ToolRegistry
from tests.scenarios.test_security_ai_fusion import PINS


@pytest.fixture(scope="module")
def saved_packages():
    root = Path(__file__).parents[3] / "tests/fixtures/security_ai_packages"
    return tuple(load_package(root / kind, expected_manifest_digest=pin) for kind, pin, _ in PINS)


@pytest.mark.parametrize("profile", tuple(DeploymentProfile))
def test_shared_runtime_injection_and_deny_authority(
    tmp_path, profile, saved_packages, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("No provider request in composition validation")

    monkeypatch.setattr(OpenAICompatibleClient, "_post", forbidden)
    path = tmp_path / f"{profile.value.lower()}-configured.sqlite"
    store = open_application_store(path, create=True)
    migrate_ingestion(store)
    source = EventIngestor(store)
    registry = ToolRegistry()
    for tool in (demo_read_tool(source), demo_network_tool(source), demo_response_tool()):
        registry.register(tool)
    llm = DemoLLM(source)
    analysis = PackagedAnalysis(source, saved_packages)
    invocations = []

    async def model_analysis(state):
        before = state.model_dump_json()
        result = await analysis(state)
        assert state.model_dump_json() == before
        invocations.append(result)
        return result

    composition = compose_application(
        store,
        deployment=DeploymentDescriptor(profile=profile),
        registry=registry,
        llm_client=llm,
        ingestion=source,
        model_analysis=model_analysis,
    )
    service = composition.service
    assert composition.deployment.profile == profile
    assert type(service.runtime_factory()) is SOCRuntime
    assert service.store is store and path.exists()
    for action in (
        HumanAction.APPROVE_PROMOTED_TOOL,
        HumanAction.AUTHORIZE_STATE_CHANGE,
        HumanAction.PROMOTE_IMPROVEMENT_ARTIFACT,
        HumanAction.ROLLBACK_IMPROVEMENT_ARTIFACT,
    ):
        with pytest.raises(HumanAuthorizationDenied):
            service.authority.verify(
                credential="not-a-confirmation", action=action, binding_digest="0" * 64
            )
    identity = service.ingest(scenario_event("b")).incident_id
    initial = service.incident(identity).state

    async def advance():
        workflow = service.start(identity)
        for _ in range(16):
            if workflow.waiting_for_human or workflow.terminal:
                return workflow
            workflow = await service.step(
                identity,
                StepRequest(
                    run_id=workflow.workflow_id, expected_revision=workflow.checkpoint_revision
                ),
            )
        raise AssertionError("Shared workflow did not stop")

    workflow = asyncio.run(advance())
    assert workflow.waiting_for_human
    assert len(invocations) == 1 and llm.analysis_calls == 1
    assert len(invocations[0].signals) == 1
    assert invocations[0].contributions[0].model_kind == "authentication_anomaly"
    assert service.checkpoint(identity).artifacts.execution_intent_id is None
    final = service.incident(identity).state
    assert (final.severity, final.status) == (initial.severity, initial.status)
    assert len(final.evidence) == 1
    reopened = open_application_store(path)
    assert reopened.load(identity).state == final
    assert service.dashboard_self_improvement(lambda _: True).active.state == "NONE"


def test_descriptor_is_immutable_metadata_only():
    descriptor = DeploymentDescriptor(profile=DeploymentProfile.DESKTOP)
    assert descriptor.model_dump(mode="json") == {"profile": "DESKTOP"}
    with pytest.raises(ValidationError):
        descriptor.profile = DeploymentProfile.SERVER
    for field in ("authority", "allow_write", "bypass_approval", "role", "policy_overrides"):
        with pytest.raises(ValidationError):
            DeploymentDescriptor.model_validate({"profile": "SERVER", field: True})


def test_dependency_direction_and_compatibility_alias():
    assert CompatibleAnalysis is PackagedAnalysis
    root = Path(__file__).parents[3] / "src/soc_agent"
    for path in (root / "application.py", root / "security_ai/model_analysis.py"):
        imports = [
            node.module or ""
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.ImportFrom)
        ]
        assert not any(name.startswith(("soc_agent.demo", "soc_agent.live")) for name in imports)
        assert "soc_agent.api.http" not in imports
    for area in ("investigation/runtime", "policy", "review", "security_ai", "llm"):
        for path in (root / area).rglob("*.py"):
            imports = [
                node.module or ""
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                if isinstance(node, ast.ImportFrom)
            ]
            assert "soc_agent.deployment" not in imports
