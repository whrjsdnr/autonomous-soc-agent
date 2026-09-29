from uuid import uuid4

import pytest

from soc_agent.execution.durable import Lifecycle
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.policy import PolicyDecision
from soc_agent.response.promotion.errors import PromotionPolicyDenied, ToolMetadataChanged


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("tool_name", "other_tool"),
        ("canonical_input", '{"target":"other"}'),
        ("incident_id", uuid4()),
        ("promoted_action_id", "a" * 64),
        ("approval_id", uuid4()),
    ],
)
async def test_forged_intent_cannot_invoke(durable, field, value):
    store, record, executor, _ = durable
    claim = store.claim(record.intent.execution_intent_id, claimant="worker")
    forged = claim.model_copy(
        update={
            "intent": claim.intent.model_copy(
                update={"binding": claim.intent.binding.model_copy(update={field: value})}
            )
        }
    )
    with pytest.raises(ClaimConflict):
        await executor.execute_claim(forged)
    assert store.load(record.intent.execution_intent_id) == claim


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["policy", "metadata"])
async def test_current_validation_prevents_invocation(durable, change):
    store, record, executor, workflow = durable
    if change == "policy":
        workflow[2].override = PolicyDecision.DENY
        expected = PromotionPolicyDenied
    else:
        from dataclasses import replace

        registry = workflow[0][5]
        tool = registry.get("test_response")
        registry._tools["test_response"] = replace(
            tool, metadata=tool.metadata.model_copy(update={"description": "changed"})
        )
        expected = ToolMetadataChanged
    with pytest.raises(expected):
        await executor.execute(record.intent.execution_intent_id, claimant="worker")
    assert store.load(record.intent.execution_intent_id).state == Lifecycle.FAILED


@pytest.mark.asyncio
async def test_expired_claim_cannot_invoke(durable, monkeypatch):
    from tests.unit.durable_execution.test_lifecycle import expire

    store, record, executor, _ = durable
    claim = store.claim(record.intent.execution_intent_id, claimant="worker")
    expire(monkeypatch)
    with pytest.raises(ClaimConflict):
        await executor.execute_claim(claim)
    assert store.load(record.intent.execution_intent_id).invocation_started_at is None


def test_immutable_intent_and_identity_tampering(durable):
    from pydantic import ValidationError

    from soc_agent.execution.durable import ExecutionIntent

    _, record, _, _ = durable
    with pytest.raises(ValidationError):
        record.intent.idempotency_key = "a" * 64
    payload = record.intent.model_dump(mode="json")
    payload["execution_intent_id"] = "a" * 64
    with pytest.raises(ValidationError):
        ExecutionIntent.model_validate(payload)
