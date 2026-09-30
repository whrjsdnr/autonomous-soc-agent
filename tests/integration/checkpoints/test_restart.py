import pytest

from soc_agent.execution.durable import Lifecycle, ReconciledOutcome, ReconciliationRequest
from soc_agent.investigation.runtime import WorkflowStep as Step
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.review.identity import content_digest
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready, review_for
from tests.unit.promotion.conftest import approve, promoted

from .conftest import restart


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "advances,expected",
    [(0, Step.OBSERVE), (1, Step.ROUTE), (2, Step.ANALYZE), (3, Step.DECIDE), (4, Step.GOVERN)],
)
async def test_checkpoint_trace_roundtrip_and_correct_resume(runtime_case, advances, expected):
    c = runtime_case(durable_workflow=True)
    for _ in range(advances):
        await c.runtime.advance(c.incident_id)
    before = c.runtime.artifacts(c.incident_id)
    trace = c.runtime.trace(c.incident_id)
    checkpoint, saved_trace = CheckpointStore(c.store).load(c.incident_id)
    assert saved_trace == trace and checkpoint.result.next_step == expected
    restart(c)
    restored = c.runtime.restore(c.incident_id)
    assert restored.next_step == expected
    assert c.runtime.artifacts(c.incident_id) == before
    assert c.runtime.trace(c.incident_id) == trace
    result = await c.runtime.advance(c.incident_id)
    assert result.current_step == expected
    assert c.runtime.trace(c.incident_id).entries[: len(trace.entries)] == trace.entries
    assert c.llm.calls == (1 if advances >= 2 else 0)


@pytest.mark.asyncio
async def test_investigation_and_loop_guard_survive_restart(runtime_case):
    c = runtime_case(durable_workflow=True, evidence=False, severities=("high",), limit=1)
    for _ in range(3):
        await c.runtime.advance(c.incident_id)
    assert c.mocks["inspect_logs"].call_count == 1
    restart(c)
    c.runtime.restore(c.incident_id)
    await decision_ready(c)
    result = await c.runtime.advance(c.incident_id)
    assert result.waiting_for_human and result.failure == "investigation_loop_guard"
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_write_wait_restart_then_fresh_human_artifacts(runtime_case):
    c = runtime_case(durable_workflow=True, severities=("high",))
    _, _, waiting = await promoted_ready(c, write=True, approval=False)
    assert waiting.waiting_for_human and waiting.next_step == Step.GOVERN
    before = c.runtime.artifacts(c.incident_id)
    prefix = c.runtime.trace(c.incident_id)
    restart(c)
    assert c.runtime.restore(c.incident_id).waiting_for_human
    assert (await c.runtime.advance(c.incident_id, execute=True)).waiting_for_human
    assert c.mocks["test_response"].call_count == 0 and c.llm.calls == 1
    plan = c.runtime.artifacts(c.incident_id).response_plan
    workflow = (None, plan, c.policy, c.promotion_service, c.approvals, c.bridge, c.authority)
    value = promoted(workflow, "test_response")
    approval = approve(workflow, value)
    result = await c.runtime.advance(
        c.incident_id, promoted=value, approval_id=approval.approval_id
    )
    assert result.next_step == Step.ACT
    assert (await c.runtime.advance(c.incident_id, execute=True)).next_step == Step.EVALUATE
    assert (await c.runtime.advance(c.incident_id)).terminal
    assert c.runtime.artifacts(c.incident_id).assessment == before.assessment
    assert c.runtime.trace(c.incident_id).entries[: len(prefix.entries)] == prefix.entries
    assert c.mocks["test_response"].call_count == 1
    restart(c)
    assert c.runtime.restore(c.incident_id).terminal
    await c.runtime.advance(c.incident_id, execute=True)
    assert c.mocks["test_response"].call_count == 1


@pytest.mark.asyncio
async def test_incident_review_pause_restart_without_reanalysis(runtime_case):
    c = runtime_case(durable_workflow=True)
    await decision_ready(c)
    review = review_for(c)
    restart(c)
    c.runtime.restore(c.incident_id)
    assert (await c.runtime.advance(c.incident_id)).waiting_for_human
    assert (await c.runtime.advance(c.incident_id, review=review)).next_step == Step.GOVERN
    assert c.llm.calls == 1
    first = c.runtime.trace(c.incident_id)
    await c.runtime.advance(c.incident_id)
    second = c.runtime.trace(c.incident_id)
    await c.runtime.advance(c.incident_id)
    assert c.runtime.trace(c.incident_id) == second
    assert second.entries[: len(first.entries)] == first.entries


@pytest.mark.asyncio
async def test_uncertain_restart_reconcile_without_retry(runtime_case):
    c = runtime_case(durable_workflow=True, responses=[TimeoutError("Unknown remote outcome")])
    await promoted_ready(c)
    await c.runtime.advance(c.incident_id, execute=True)
    identity = c.runtime.artifacts(c.incident_id).execution_intent_id
    restart(c)
    assert c.runtime.restore(c.incident_id).next_step == Step.RECOVER
    for _ in range(3):
        assert (await c.runtime.advance(c.incident_id, execute=True)).next_step == Step.RECOVER
    assert c.mocks["inspect_logs"].call_count == 1
    record = c.executor.store.load(identity)
    assert record.state == Lifecycle.UNCERTAIN
    request = ReconciliationRequest(
        execution_intent_id=identity,
        incident_id=c.incident_id,
        expected_revision=record.revision,
        outcome=ReconciledOutcome.CONFIRMED_SUCCEEDED,
        reason="Verified externally",
        references=("ticket",),
    )
    token = c.authority.confirm(
        subject="approver-bob",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    c.executor.store.reconcile(request, credential=token, authority=c.authority)
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.EVALUATE
    assert (await c.runtime.advance(c.incident_id)).terminal
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_act_restart_uses_existing_durable_approval_not_checkpoint_authority(runtime_case):
    c = runtime_case(durable_workflow=True, severities=("high",))
    _, _, result = await promoted_ready(c, write=True)
    assert result.next_step == Step.ACT
    identity = c.runtime.artifacts(c.incident_id).execution_intent_id
    assert c.executor.store.load(identity).state == Lifecycle.PENDING
    restart(c)
    assert c.runtime.restore(c.incident_id).next_step == Step.ACT
    assert (await c.runtime.advance(c.incident_id)).waiting_for_human
    assert c.mocks["test_response"].call_count == 0
    assert (await c.runtime.advance(c.incident_id, execute=True)).next_step == Step.EVALUATE
    assert c.executor.store.load(identity).state == Lifecycle.SUCCEEDED
    assert c.mocks["test_response"].call_count == 1


@pytest.mark.asyncio
async def test_stale_snapshot_rejected(runtime_case):
    c = runtime_case(durable_workflow=True)
    await decision_ready(c)
    snapshot = c.store.load(c.incident_id)
    c.store.append_evidence(
        snapshot.anchor,
        Evidence(
            incident_id=c.incident_id,
            source="new",
            summary="New evidence",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    restart(c)
    with pytest.raises(StaleSnapshotError):
        c.runtime.restore(c.incident_id)
    assert c.llm.calls == 1


@pytest.mark.asyncio
async def test_restored_intent_still_revalidates_current_policy(runtime_case):
    from soc_agent.policy import PolicyDecision

    c = runtime_case(durable_workflow=True, severities=("high",))
    await promoted_ready(c, write=True)
    restart(c)
    c.runtime.restore(c.incident_id)
    c.policy.override = PolicyDecision.DENY
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.failure == "execution_failed"
    assert c.mocks["test_response"].call_count == 0
