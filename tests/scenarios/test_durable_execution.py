"""Real saved models; Mock LLM, test human confirmation and mock Tools only."""

import pytest
from tests.scenarios.test_response_promotion_execution import environment as environment
from tests.scenarios.test_response_promotion_execution import packages as packages
from tests.unit.durable_execution.test_lifecycle import expire
from tests.unit.durable_execution.test_reconciliation import request_for
from tests.unit.promotion.conftest import approve, promoted

from soc_agent.execution.durable import (
    DurableExecutor,
    ExecutionStore,
    Lifecycle,
    ReconciledOutcome,
    migrate,
)
from soc_agent.execution.durable.errors import ClaimConflict
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    ["read", "write", "before_invocation", "uncertain", "reconcile", "stale", "restart_replay"],
)
async def test_durable_saved_model_pipeline(environment, scenario, monkeypatch):
    workflow, read, write = environment
    governance = workflow[0][3]
    migrate(governance.database)
    store = ExecutionStore(governance)
    value = promoted(workflow, "inspect_logs" if scenario == "read" else "test_response")
    approval = None if scenario == "read" else approve(workflow, value)
    record = store.create(
        workflow[5], value, approval_id=approval.approval_id if approval else None
    )
    identity = record.intent.execution_intent_id
    assert read.call_count == write.call_count == 0
    executor = DurableExecutor(store=store, registry=workflow[0][5], policy=workflow[2])
    if scenario == "stale":
        governance.append_evidence(
            value.content.current_snapshot,
            Evidence(
                incident_id=value.content.request.target.incident_id,
                source="later",
                summary="new evidence",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
        with pytest.raises(StaleSnapshotError):
            await executor.execute(identity, claimant="worker")
        assert store.load(identity).state == Lifecycle.FAILED
        assert write.call_count == 0
    elif scenario in ("before_invocation", "uncertain", "reconcile"):
        claim = store.claim(identity, claimant="stopped-worker")
        if scenario != "before_invocation":
            store.transition(claim, Lifecycle.EXECUTING)
        store = ExecutionStore(SQLiteGovernanceStore(governance.database.path))
        expire(monkeypatch)
        store.recover()
        recovered = store.load(identity)
        assert recovered.state == (
            Lifecycle.PENDING if scenario == "before_invocation" else Lifecycle.UNCERTAIN
        )
        assert read.call_count == write.call_count == 0
        if scenario == "reconcile":
            request = request_for(recovered, ReconciledOutcome.CONFIRMED_SUCCEEDED)
            authority = workflow[6]
            token = authority.confirm(
                subject="reviewer-alice",
                action=HumanAction.RECONCILE_EXECUTION,
                digest=content_digest(request),
            )
            assert (
                store.reconcile(request, credential=token, authority=authority).state
                == Lifecycle.SUCCEEDED
            )
        if scenario != "before_invocation":
            with pytest.raises(ClaimConflict):
                store.claim(identity, claimant="retry")
    else:
        await executor.execute(identity, claimant="worker")
        reopened = ExecutionStore(SQLiteGovernanceStore(governance.database.path))
        assert reopened.load(identity).state == Lifecycle.SUCCEEDED
        assert read.call_count + write.call_count == 1
        assert [e.event_type for e in reopened.events(identity)] == [
            "intent_created",
            "claimed",
            "invocation_boundary",
            "succeeded",
        ]
        if scenario == "restart_replay":
            fresh = DurableExecutor(store=reopened, registry=workflow[0][5], policy=workflow[2])
            with pytest.raises(ClaimConflict):
                await fresh.execute(identity, claimant="restarted")
            assert write.call_count == 1
