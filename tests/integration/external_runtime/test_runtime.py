"""Actual SOCRuntime/SQLite/guards; synthetic normalized predictions and scripted LLM."""

from uuid import uuid4

import pytest
from tests.bounded_support import Query, Reputation
from tests.external_advisory_support import responses
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace

from soc_agent.application import compose_application
from soc_agent.approval import ApprovalManager
from soc_agent.approval.errors import ApprovalNotFoundError
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.external.read_only_backend import CapabilityDenied
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry


@pytest.fixture
def host(bundle, workspace):
    _, context, _, _, _ = bundle
    store = RuntimeGovernanceStore.activate_validation_workspace(workspace)
    calls = {"read": 0, "write": 0}

    async def read(value):
        calls["read"] += 1
        return Reputation(reputation="UNKNOWN")

    async def write(value):
        calls["write"] += 1
        pytest.fail("External WRITE handler invoked")

    registry = ToolRegistry()
    for name, handler, permission, risk in (
        ("source_lookup", read, "network_read", "read_only"),
        ("disable_account", write, "system_write", "high"),
    ):
        registry.register(
            Tool(
                metadata=ToolMetadata(
                    name=name,
                    description="Synthetic test handler",
                    permission=permission,
                    risk_level=risk,
                ),
                input_model=Query,
                output_model=Reputation,
                handler=handler,
            )
        )
    plan, assessment = responses(context)
    client = MockLLMClient([assessment, plan, assessment, plan])
    composition = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=client,
    )
    store.boundary.attach(context)
    yield composition, store, context, registry, client, calls
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_actual_runtime_assessment_decision_read_restart_atomic(host):
    composition, store, context, registry, client, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    for _ in range(12):
        result = await runtime.advance(incident)
        if result.waiting_for_human or result.terminal:
            break
    assert not result.terminal, runtime.trace(incident)
    assert result.waiting_for_human
    assert calls == {"read": 1, "write": 0}
    assert runtime.artifacts(incident).decision is not None
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM external_decision_receipts").fetchone()[0] > 0
        )
        assert connection.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0] > 0
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 1
    restored = composition.service.runtime_factory()
    assert restored.restore(incident) == runtime.checkpoint(incident).result
    assert restored.artifacts(incident) == runtime.artifacts(incident)
    # Restore rotates the session; old capability cannot submit another step.
    with pytest.raises(CapabilityDenied):
        await runtime.advance(incident)


@pytest.mark.asyncio
async def test_direct_executor_handler_approval_and_alias_denied(host):
    composition, store, context, registry, client, calls = host
    incident = context.input_snapshot.incident_id
    action = ActionProposal(
        incident_id=incident,
        tool_name="disable_account",
        tool_input={"indicator": "synthetic.invalid"},
    )
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    with pytest.raises(CapabilityDenied):
        await executor.execute(action)
    with pytest.raises(CapabilityDenied):
        executor.request_approval(action, reason="Attempt")
    tool = registry.get("disable_account")
    with pytest.raises(CapabilityDenied):
        await tool.execute(action.input_payload())
    with pytest.raises(CapabilityDenied):
        await tool.handler(Query(indicator="synthetic.invalid"))
    unbound = ToolRegistry()
    unbound.register(tool)
    other = GovernedExecutor(registry=unbound, policy=PolicyEngine(), approvals=ApprovalManager())
    # Policy still needs approval; forging approval never substitutes for bound leaf dispatch.
    with pytest.raises(ApprovalNotFoundError):
        await other.execute(action, approval_id=uuid4())
    assert calls["write"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "point", ["EVIDENCE_FLUSHED", "RECEIPTS_SAVED", "BEFORE_PUBLICATION_COMMIT"]
)
async def test_publication_failure_rolls_back_receipts_checkpoint_and_state(
    host, monkeypatch, point
):
    composition, store, context, registry, client, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    await runtime.advance(incident)  # OBSERVE -> ROUTE
    await runtime.advance(incident)  # ROUTE -> ANALYZE
    before = runtime.checkpoint(incident)
    with store.database.transaction(write=False) as connection:
        old_audit = connection.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0]
        old_publications = connection.execute(
            "SELECT COUNT(*) FROM external_runtime_publications"
        ).fetchone()[0]

    def fail(stage):
        if stage == point:
            raise RuntimeError("Injected transaction failure")

    monkeypatch.setattr(store, "fault", fail)
    with pytest.raises(RuntimeError, match="Injected"):
        await runtime.advance(incident)
    with store.database.transaction(write=False) as connection:
        row = connection.execute("SELECT revision,claim FROM workflow_checkpoints").fetchone()
        assert row[0] == before.revision and row[1] is not None
        assert (
            connection.execute("SELECT COUNT(*) FROM external_assessment_runs").fetchone()[0] == 0
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM external_runtime_publications").fetchone()[0]
            == old_publications
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0]
            == old_audit
        )
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 0
    from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight

    with pytest.raises(WorkflowInFlight):
        composition.service.runtime_factory().restore(incident)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table", ["external_contexts", "external_receipts", "external_runtime_publications"]
)
async def test_real_resume_rejects_tampered_context_receipt_publication(host, table):
    composition, store, context, *_ = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    for _ in range(4):
        await runtime.advance(incident)
    with store.database.transaction() as connection:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
    from soc_agent.review.persistence.models import StoredDataError

    with pytest.raises(StoredDataError):
        composition.service.runtime_factory().restore(incident)


@pytest.mark.asyncio
async def test_no_model_facts_prompt_injection_or_write_authority(host):
    composition, store, context, registry, client, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    for _ in range(8):
        await runtime.advance(incident)
    assert any("EXTERNAL MODEL CONTEXT" in request.user_prompt for request in client.requests)
    assert all(
        "not authority" in request.system_prompt.lower()
        or "advisory" in request.system_prompt.lower()
        for request in client.requests
    )
    saved = store.load(incident)
    assert saved.state.severity.value == "info"
    assert not saved.state.observations and not saved.state.hypotheses
    with pytest.raises(CapabilityDenied):
        store.compare_and_apply(saved.anchor, uuid4(), lambda _: None)
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_audit_failure_never_invokes_write_handler(host):
    composition, store, context, registry, client, calls = host
    with store.database.transaction() as connection:
        connection.execute(
            "CREATE TRIGGER fail_security_audit BEFORE INSERT ON external_security_audit "
            "BEGIN SELECT RAISE(ABORT,'fault'); END"
        )
    # Exact extension schema rejects the unauthorized trigger even before dispatch.
    from soc_agent.review.persistence.models import StoredDataError

    with pytest.raises(StoredDataError):
        await registry.get("disable_account").execute({"indicator": "synthetic.invalid"})
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_explicit_reconciliation_closes_failed_read_without_replay(host, monkeypatch):
    composition, store, context, _, _, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    await runtime.advance(incident)
    await runtime.advance(incident)
    saved = runtime.checkpoint(incident)

    def fault(point):
        if point == "BEFORE_PUBLICATION_COMMIT":
            raise RuntimeError("Injected interrupted publication")

    monkeypatch.setattr(store, "fault", fault)
    with pytest.raises(RuntimeError):
        await runtime.advance(incident)
    monkeypatch.setattr(store, "fault", lambda _: None)
    recovered = composition.service.reconcile_external_interruption(
        incident, run_id=saved.run_id, revision=saved.revision
    )
    assert recovered.terminal and recovered.failure.value == "execution_uncertain"
    restored = composition.service.runtime_factory()
    assert restored.restore(incident) == recovered
    assert calls == {"read": 0, "write": 0}
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM external_security_audit "
                "WHERE payload LIKE '%CHECKPOINT_RECOVERED_NO_REPLAY%'"
            ).fetchone()[0]
            == 1
        )


@pytest.mark.asyncio
async def test_private_runtime_stage_cannot_bypass_scope(host):
    composition, _, context, _, _, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    with pytest.raises(CapabilityDenied):
        await runtime._advance_checked(incident)
    assert calls == {"read": 0, "write": 0}


@pytest.mark.asyncio
async def test_valid_legacy_approval_does_not_authorize_bound_leaf(host):
    _, _, context, registry, _, calls = host
    manager = ApprovalManager()
    action = ActionProposal(
        incident_id=context.input_snapshot.incident_id,
        tool_name="disable_account",
        tool_input={"indicator": "synthetic.invalid"},
    )
    # An independently trusted legacy manager can create a real approval; it cannot
    # remove the target handler's external read-only disposition.
    unbound = ToolRegistry()
    unbound.register(registry.get("disable_account"))
    executor = GovernedExecutor(registry=unbound, policy=PolicyEngine(), approvals=manager)
    request = executor.request_approval(action, reason="Synthetic replay attempt")
    manager.approve(request.approval_id, actor="synthetic-reviewer")
    with pytest.raises(CapabilityDenied):
        await executor.execute(action, approval_id=request.approval_id)
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_audit_writer_failure_is_fail_closed(host, monkeypatch):
    _, _, _, registry, _, calls = host
    import soc_agent.security_ai.external.runtime_guard as module

    def unavailable(*args, **kwargs):
        raise OSError("Injected audit storage unavailable")

    monkeypatch.setattr(module, "audit", unavailable)
    with pytest.raises(OSError):
        await registry.get("disable_account").execute({"indicator": "synthetic.invalid"})
    assert calls["write"] == 0


def _crash_publication(path: str, incident_text: str) -> None:
    """Spawn-safe worker opens its own SQLite handles; abrupt exit during transaction."""
    import asyncio
    import os
    from uuid import UUID

    store = RuntimeGovernanceStore(path)
    incident = UUID(incident_text)
    with store.database.transaction(write=False) as connection:
        digest = connection.execute(
            "SELECT payload FROM external_runtime_incidents WHERE incident_id=?",
            (incident_text,),
        ).fetchone()[0]
    import json

    from soc_agent.security_ai.external.storage import ExternalContextStore

    context = ExternalContextStore(store.database.path, database=store.database).load_context(
        json.loads(digest)["context_digest"]
    )
    registry = ToolRegistry()

    async def read(value):
        return Reputation(reputation="UNKNOWN")

    registry.register(
        Tool(
            ToolMetadata(
                name="source_lookup",
                description="Synthetic read",
                permission="network_read",
                risk_level="read_only",
            ),
            Query,
            Reputation,
            read,
        )
    )
    _, assessment = responses(context)
    composition = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=MockLLMClient([assessment]),
    )
    runtime = composition.service.runtime_factory()
    runtime.restore(incident)

    def crash(point):
        if point == "RECEIPTS_SAVED":
            os._exit(23)

    store.fault = crash
    asyncio.run(runtime.advance(incident))
    raise AssertionError("Crash point not executed")


@pytest.mark.asyncio
async def test_actual_process_exit_rolls_back_and_requires_reconciliation(host):
    import multiprocessing

    from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight

    composition, store, context, _, _, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    await runtime.advance(incident)
    await runtime.advance(incident)
    saved = runtime.checkpoint(incident)
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_publication, args=(str(store.database.path), str(incident))
    )
    process.start()
    process.join(45)
    if process.is_alive():
        process.terminate()
        process.join(10)
        pytest.fail("Crash worker exceeded deterministic budget")
    assert process.exitcode == 23
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM external_assessment_runs").fetchone()[0] == 0
        )
        assert connection.execute("SELECT revision FROM incidents").fetchone()[0] == 0
    with pytest.raises(WorkflowInFlight):
        composition.service.runtime_factory().restore(incident)
    result = composition.service.reconcile_external_interruption(
        incident, run_id=saved.run_id, revision=saved.revision
    )
    assert result.terminal
    assert calls == {"read": 0, "write": 0}


@pytest.mark.asyncio
async def test_missing_required_artifacts_cannot_downgrade_to_legacy(bundle, workspace, tmp_path):
    from soc_agent.review.persistence.models import StoredDataError
    from soc_agent.security_ai.external.service import ExternalSecurityAIService, ModelInput

    _, context, *_ = bundle
    store = RuntimeGovernanceStore.activate_validation_workspace(workspace)
    registry = ToolRegistry()

    async def read(value):
        return Reputation(reputation="UNKNOWN")

    registry.register(
        Tool(
            ToolMetadata(
                name="source_lookup",
                description="Synthetic read",
                permission="network_read",
                risk_level="read_only",
            ),
            Query,
            Reputation,
            read,
        )
    )
    app = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=MockLLMClient([]),
    )
    app.service.external_ai = ExternalSecurityAIService(
        store.boundary, artifacts=tmp_path / "absent"
    )
    incident = context.input_snapshot.incident_id
    inputs = tuple(
        ModelInput(binding=r.binding, observation=r.observation) for r in context.results
    )
    with pytest.raises(ValueError):
        app.service.analyze_external(incident, inputs)
    with pytest.raises(StoredDataError):
        app.service.runtime_factory().start(incident)
    # A second store with no attached in-memory guard still sees the durable requirement.
    reopened = RuntimeGovernanceStore(store.database.path)
    saved = reopened.load(incident)
    with pytest.raises(CapabilityDenied):
        reopened.compare_and_apply(saved.anchor, uuid4(), lambda _: None)
    with store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM workflow_checkpoints").fetchone()[0] == 0
        assert (
            "FAILED"
            in connection.execute("SELECT payload FROM external_runtime_requirements").fetchone()[0]
        )


@pytest.mark.asyncio
async def test_actual_authenticated_headless_read_and_bad_write_request(host):
    from tests.integration.api.conftest import TestAccess, call
    from tests.unit.identity.conftest import Boundary

    from soc_agent.api import SOCApplication
    from soc_agent.review.authentication import HumanActionContext
    from soc_agent.review.authority import HumanAction
    from soc_agent.review.authorization import HumanRole

    composition, store, context, _, _, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    for _ in range(4):
        await runtime.advance(incident)
    identity = Boundary()
    token = identity.issue(
        HumanActionContext(
            incident_id=incident,
            action=HumanAction.RECORD_REVIEW,
            binding_digest="a" * 64,
            decision_id="b" * 64,
        ),
        (HumanRole.ADMIN,),
    )
    app = SOCApplication(
        lambda: composition.service,
        provider=identity.provider,
        provider_id="test-identity",
        access=TestAccess(),
    )
    status, body = await call(app, "GET", f"/incidents/{incident}/workflow", token=token)
    assert status == 200, body
    status, _ = await call(
        app,
        "POST",
        f"/incidents/{incident}/approval-requests",
        {"tool_name": "disable_account", "execute": True},
        token,
    )
    assert status == 422
    assert calls["write"] == 0
    with store.database.transaction() as connection:
        connection.execute("UPDATE external_decision_receipts SET digest=?", ("0" * 64,))
    # The existing HTTP read route revalidates companion provenance as well as checkpoint hash.
    status, _ = await call(app, "GET", f"/incidents/{incident}/workflow", token=token)
    assert status != 200


@pytest.mark.asyncio
async def test_legacy_incident_in_runtime_store_keeps_evidence_publication(host):
    from soc_agent.state import IncidentState

    composition, store, context, _, client, calls = host
    legacy = store.register(IncidentState())
    plan, _ = responses(context)
    client._responses.clear()
    client._responses.append(plan)
    runtime = composition.service.runtime_factory()
    runtime.start(legacy.anchor.incident_id)
    for _ in range(4):
        await runtime.advance(legacy.anchor.incident_id)
    saved = store.load(legacy.anchor.incident_id)
    assert saved.anchor.revision == 1
    assert len(saved.state.evidence) == 1
    assert calls == {"read": 1, "write": 0}
    with store.database.transaction(write=False) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM external_runtime_publications WHERE incident_id=?",
                (str(legacy.anchor.incident_id),),
            ).fetchone()[0]
            == 0
        )


@pytest.mark.asyncio
async def test_issued_capability_identity_expiry_cross_incident_and_leaf(host, monkeypatch):
    from dataclasses import replace

    import soc_agent.security_ai.external.runtime_guard as module

    composition, store, context, registry, _, calls = host
    incident = context.input_snapshot.incident_id
    runtime = composition.service.runtime_factory()
    runtime.start(incident)
    grant = runtime._external._grants[incident]
    with pytest.raises(CapabilityDenied):
        with store.boundary.scope(incident, replace(grant)):
            pytest.fail("Copied capability accepted")
    with pytest.raises(CapabilityDenied):
        with store.boundary.scope(uuid4(), grant):
            pytest.fail("Cross incident capability accepted")
    with store.boundary.scope(incident, grant):
        # Even an authentic READ capability cannot call the raw handler outside dispatch.
        with pytest.raises(CapabilityDenied):
            await registry.get("source_lookup").handler(Query(indicator="synthetic.invalid"))
        with pytest.raises(CapabilityDenied):
            composition.service.bridge._approvals.create(
                incident_id=incident,
                metadata=registry.get("disable_account").metadata,
                reason="Synthetic approval attempt",
            )
    monkeypatch.setattr(module, "monotonic", lambda: grant.deadline + 1)
    with pytest.raises(CapabilityDenied):
        await runtime.advance(incident)
    assert calls == {"read": 0, "write": 0}


@pytest.mark.asyncio
async def test_external_read_tool_cannot_redirect_incident_payload(bundle, workspace):
    from soc_agent.desktop import ReadReportInput

    _, context, *_ = bundle
    store = RuntimeGovernanceStore.activate_validation_workspace(workspace)
    calls = []

    async def sensitive_read(value):
        calls.append(value)
        pytest.fail("Cross-incident read handler invoked")

    registry = ToolRegistry()
    registry.register(
        Tool(
            ToolMetadata(
                name="incident_read",
                description="Read one incident",
                permission="system_read",
                risk_level="read_only",
            ),
            ReadReportInput,
            Reputation,
            sensitive_read,
        )
    )
    app = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=MockLLMClient([]),
    )
    store.boundary.attach(context)
    runtime = app.service.runtime_factory()
    incident = context.input_snapshot.incident_id
    runtime.start(incident)
    action = ActionProposal(
        incident_id=incident, tool_name="incident_read", tool_input={"incident_id": str(uuid4())}
    )
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    with runtime._external.step(incident):
        with pytest.raises(CapabilityDenied, match="TOOL_INPUT_INCIDENT_MISMATCH"):
            await executor.execute(action)
    assert calls == []


@pytest.mark.asyncio
async def test_same_runtime_cas_collision_preserves_task_local_evidence(bundle, workspace):
    import asyncio

    from soc_agent.investigation.runtime.persistence.models import WorkflowInFlight

    _, context, *_ = bundle
    store = RuntimeGovernanceStore.activate_validation_workspace(workspace)
    started, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def read(value):
        calls.append(value)
        started.set()
        await release.wait()
        return Reputation(reputation="UNKNOWN")

    registry = ToolRegistry()
    registry.register(
        Tool(
            ToolMetadata(
                name="source_lookup",
                description="Synthetic read",
                permission="network_read",
                risk_level="read_only",
            ),
            Query,
            Reputation,
            read,
        )
    )
    plan, assessment = responses(context)
    app = compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=MockLLMClient([assessment, plan]),
    )
    store.boundary.attach(context)
    runtime = app.service.runtime_factory()
    incident = context.input_snapshot.incident_id
    runtime.start(incident)
    for _ in range(5):
        await runtime.advance(incident)
    pending = asyncio.create_task(runtime.advance(incident))
    try:
        await asyncio.wait_for(started.wait(), 10)
        with pytest.raises(WorkflowInFlight):
            await runtime.advance(incident)
    finally:
        release.set()
    await asyncio.wait_for(pending, 10)
    assert len(calls) == 1
    saved = store.load(incident)
    assert saved.anchor.revision == 1 and len(saved.state.evidence) == 2
    restored = app.service.runtime_factory()
    restored.restore(incident)
    assert restored.artifacts(incident).snapshot == saved.anchor
