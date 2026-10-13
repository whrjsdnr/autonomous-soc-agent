"""Real capability, policy, executor and secure SQLite; stub READ and WRITE spy."""

import asyncio
import copy
import pickle
from uuid import UUID, uuid4

import pytest
from tests.bounded_support import Query, Reputation
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ActionAlreadyAttemptedError
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.external import read_only_backend as module
from soc_agent.security_ai.external.read_only_backend import (
    CapabilityDenied,
    ReadOnlyBackend,
    ReadOnlyCapability,
    open_read_only_backend,
)
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry


@pytest.fixture
def harness(bundle):
    store, context, run, receipt, expected = bundle
    store.save_bundle(context, run, receipt)
    calls = {"read": 0, "write": 0}

    async def read(value: Query):
        calls["read"] += 1
        return Reputation(reputation="UNKNOWN")

    async def write(value: Query):
        calls["write"] += 1
        pytest.fail("WRITE spy invoked")

    registry = ToolRegistry()
    for name, handler, permission, risk in (
        ("source_lookup", read, "network_read", "read_only"),
        ("disable_account", write, "system_write", "high"),
    ):
        registry.register(
            Tool(
                metadata=ToolMetadata(
                    name=name, description="Synthetic stub", permission=permission, risk_level=risk
                ),
                input_model=Query,
                output_model=Reputation,
                handler=handler,
            )
        )
    backend, cap = open_read_only_backend(
        store=store, requirement=expected, registry=registry, allowed_tools=("source_lookup",)
    )
    action = ActionProposal(
        incident_id=expected.incident_id,
        tool_name="source_lookup",
        tool_input={"indicator": "synthetic.invalid"},
    )
    kwargs = dict(
        capability=cap,
        session_id=backend.session_id,
        context_digest=context.context_digest,
        contract_version="soc-external-model-context:v2",
    )
    yield backend, action, kwargs, calls, store, registry, expected
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_real_read_and_single_action_attempt(harness):
    backend, action, kwargs, calls, *_ = harness
    result = await backend.execute(action, **kwargs)
    assert result.output.reputation == "UNKNOWN" and calls["read"] == 1
    with pytest.raises(ActionAlreadyAttemptedError):
        await backend.execute(action, **kwargs)
    assert calls["read"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "missing",
        "json",
        "clone",
        "fake_type",
        "session",
        "digest",
        "version",
        "incident",
        "write",
        "alias",
        "dynamic",
        "approval",
        "closed",
        "foreign_issuer",
    ],
)
async def test_attacks_fail_before_handler(harness, attack):
    backend, action, kwargs, calls, store, registry, expected = harness
    kwargs = dict(kwargs)
    if attack == "missing":
        kwargs.pop("capability")
    elif attack == "json":
        kwargs["capability"] = {"permission": "READ_ONLY", "approved": True}
    elif attack == "clone":
        kwargs["capability"] = object.__new__(ReadOnlyCapability)
    elif attack == "fake_type":
        kwargs["capability"] = object()
    elif attack == "session":
        kwargs["session_id"] = uuid4()
    elif attack == "digest":
        kwargs["context_digest"] = "0" * 64
    elif attack == "version":
        kwargs["contract_version"] = "soc-external-model-context:v1"
    elif attack == "incident":
        action = action.model_copy(update={"incident_id": UUID(int=999)})
    elif attack in ("write", "alias", "dynamic"):
        name = {"write": "disable_account", "alias": "source_lookup_alias", "dynamic": "eval_tool"}
        action = action.model_copy(update={"tool_name": name[attack]})
    elif attack == "approval":
        kwargs["approval_id"] = uuid4()
    elif attack == "closed":
        backend.close()
    elif attack == "foreign_issuer":
        _, kwargs["capability"] = open_read_only_backend(
            store=store, requirement=expected, registry=registry, allowed_tools=("source_lookup",)
        )
    with pytest.raises(CapabilityDenied):
        await backend.execute(action, **kwargs)
    assert calls == {"read": 0, "write": 0}
    assert len(backend.security_events) == 1
    assert "synthetic.invalid" not in repr(backend.security_events)


def test_constructor_mutation_and_serialization(harness):
    backend, _, kwargs, *_ = harness
    cap = kwargs["capability"]
    for cls in (ReadOnlyCapability, ReadOnlyBackend):
        with pytest.raises(TypeError):
            cls()
    with pytest.raises(AttributeError):
        object.__setattr__(cap, "approved", True)
    for obj in (cap, backend):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TypeError):
                operation(obj)


@pytest.mark.asyncio
async def test_expiry_and_no_clock_rollback(harness, monkeypatch):
    backend, action, kwargs, calls, *_ = harness
    monkeypatch.setattr(module, "monotonic", lambda: float("inf"))
    with pytest.raises(CapabilityDenied, match="EXPIRED"):
        await backend.execute(action, **kwargs)
    assert calls["read"] == 0


@pytest.mark.asyncio
async def test_registry_handler_wrapper_replacement(harness):
    backend, action, kwargs, calls, _, registry, _ = harness
    tool = registry.get("source_lookup")
    object.__setattr__(tool, "handler", registry.get("disable_account").handler)
    with pytest.raises(CapabilityDenied, match="REGISTRY_CHANGED"):
        await backend.execute(action, **kwargs)
    assert calls["read"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("table", ["external_contexts", "external_receipts"])
async def test_persisted_context_and_receipt_tampering(harness, table):
    backend, action, kwargs, calls, store, *_ = harness
    with store.database.transaction() as connection:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
    with pytest.raises(CapabilityDenied, match="PERSISTED_LINEAGE"):
        await backend.execute(action, **kwargs)
    assert calls["read"] == 0


@pytest.mark.asyncio
async def test_approved_write_still_denied(harness):
    backend, action, kwargs, calls, _, registry, _ = harness
    approvals = ApprovalManager()
    legacy = GovernedExecutor(registry=registry, policy=PolicyEngine(), approvals=approvals)
    write = action.model_copy(update={"tool_name": "disable_account"})
    approval = legacy.request_approval(write, reason="Synthetic authorization replay test")
    approvals.approve(approval.approval_id, actor="synthetic-reviewer")
    # The actual legacy preflight accepts the exact approval. The scoped port must not.
    legacy.preflight(write, approval_id=approval.approval_id)
    with pytest.raises(CapabilityDenied, match="APPROVAL_NOT_A_CAPABILITY"):
        await backend.execute(write, **kwargs, approval_id=approval.approval_id)
    assert calls["write"] == 0


@pytest.mark.asyncio
async def test_simultaneous_submission_only_one_read(harness):
    backend, action, kwargs, calls, *_ = harness
    results = await asyncio.gather(
        backend.execute(action, **kwargs), backend.execute(action, **kwargs), return_exceptions=True
    )
    assert sum(isinstance(r, ActionAlreadyAttemptedError) for r in results) == 1
    assert calls["read"] == 1


@pytest.mark.parametrize("names", [(), ("disable_account",), ("source_lookup", "source_lookup")])
def test_trusted_factory_rejects_unsafe_allowlist(harness, names):
    *_, store, registry, expected = harness
    with pytest.raises(CapabilityDenied):
        open_read_only_backend(
            store=store, requirement=expected, registry=registry, allowed_tools=names
        )
