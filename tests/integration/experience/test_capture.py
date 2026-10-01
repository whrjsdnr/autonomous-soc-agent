from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.experience import (
    Experience,
    ExperienceCaptureService,
    ExperienceStore,
    HistoricalOutcome,
    migrate_experiences,
)
from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.review.models import ReviewOutcome
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.tools.errors import ToolExecutionError
from tests.unit.investigation_runtime.conftest import decision_ready, promoted_ready, review_for


def capture_service(case):
    migrate_experiences(case.store.database)
    return ExperienceCaptureService(ExperienceStore(case.store))


async def finish(case):
    for _ in range(4):
        result = await case.runtime.advance(case.incident_id, execute=True)
        if result.terminal or result.next_step == WorkflowStep.RECOVER:
            return result
    raise AssertionError("No final/recovery result")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,outcome",
    [
        (None, HistoricalOutcome.SUCCEEDED),
        (ToolExecutionError("synthetic failure"), HistoricalOutcome.FAILED),
        (TimeoutError("unknown external outcome"), HistoricalOutcome.UNCERTAIN),
    ],
)
async def test_execution_capture(runtime_case, error, outcome):
    case = runtime_case(
        durable_workflow=True, severities=("high",), responses=[error] if error else None
    )
    await promoted_ready(case, write=True)
    await finish(case)
    before = case.store.load(case.incident_id)
    service = capture_service(case)
    value = service.capture(case.incident_id)
    assert value.content.execution_outcome == outcome
    assert value.content.snapshot == before.anchor
    assert case.store.load(case.incident_id) == before
    assert service.capture(case.incident_id) == value
    reopened = ExperienceStore(SQLiteGovernanceStore(case.store.database.path))
    assert reopened.get(value.experience_id) == value
    assert reopened.list_for_incident(case.incident_id) == (value,)
    kinds = {r.kind for r in value.content.references}
    assert {
        "assessment",
        "decision",
        "incident_review",
        "execution_intent",
        "tool_approval",
    } <= kinds
    assert value.content.tool_invocation_count is None
    assert value.content.orchestration_step_count == len(
        case.runtime.trace(case.incident_id).entries
    )
    assert value.content.terminal is (outcome != HistoricalOutcome.UNCERTAIN)
    with pytest.raises(ValidationError):
        value.experience_id = "0" * 64
    with pytest.raises(ValidationError):
        Experience.model_validate(value.model_dump() | {"experience_id": "0" * 64})


@pytest.mark.asyncio
async def test_waiting_and_rejection_distinct(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    service = capture_service(case)
    waiting = service.capture(case.incident_id)
    assert waiting.content.waiting_for_human and not waiting.content.terminal
    assert waiting.content.execution_outcome == HistoricalOutcome.NOT_EXECUTED
    await case.runtime.advance(case.incident_id, review=review_for(case, ReviewOutcome.REJECTED))
    await case.runtime.advance(case.incident_id)
    rejected = service.capture(case.incident_id)
    assert rejected.content.terminal
    assert rejected.content.human_disposition == ReviewOutcome.REJECTED
    assert rejected.content.execution_outcome == HistoricalOutcome.NOT_EXECUTED
    assert rejected.content.governance_outcome == "human_rejected"
    await case.runtime.advance(case.incident_id)
    assert service.capture(case.incident_id) == rejected


@pytest.mark.asyncio
async def test_expected_bindings_and_corruption(runtime_case):
    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    service = capture_service(case)
    with pytest.raises(StoredDataError):
        service.capture(case.incident_id, expected_run_id=uuid4())
    anchor = case.store.load(case.incident_id).anchor
    with pytest.raises(StoredDataError):
        service.capture(
            case.incident_id, expected_snapshot=anchor.model_copy(update={"revision": 99})
        )
    value = service.capture(case.incident_id)
    with case.store.database.transaction() as connection:
        connection.execute("UPDATE experiences SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        service.store.get(value.experience_id)
    with pytest.raises(StoredDataError):
        service.capture(case.incident_id)


@pytest.mark.asyncio
async def test_governance_block_is_not_execution_failure(runtime_case):
    from soc_agent.response.advisory import CandidateIntent

    case = runtime_case(durable_workflow=True)
    await decision_ready(case)
    await case.runtime.advance(case.incident_id, review=review_for(case))
    candidate = CandidateIntent(
        candidate_tool="unregistered_tool",
        proposed_input={"target": "host_a"},
        purpose="Test invalid candidate",
        rationale="Missing registry entry",
        evidence_ids=(case.store.load(case.incident_id).state.evidence[0].evidence_id,),
    )
    result = await case.runtime.advance(case.incident_id, candidates=(candidate,))
    assert result.failure == "governance_blocked"
    value = capture_service(case).capture(case.incident_id)
    assert value.content.governance_outcome == "blocked"
    assert value.content.human_disposition == ReviewOutcome.CHANGE_ELIGIBLE
    assert value.content.execution_outcome == HistoricalOutcome.NOT_EXECUTED


@pytest.mark.asyncio
async def test_reconciliation_is_new_historical_outcome_without_retry(runtime_case):
    from soc_agent.execution.durable.models import ReconciledOutcome, ReconciliationRequest
    from soc_agent.review import HumanAction
    from soc_agent.review.identity import content_digest

    case = runtime_case(durable_workflow=True, responses=[TimeoutError("lost reply")])
    await promoted_ready(case)
    await finish(case)
    service = capture_service(case)
    uncertain = service.capture(case.incident_id)
    identity = case.runtime.artifacts(case.incident_id).execution_intent_id
    record = case.executor.store.load(identity)
    request = ReconciliationRequest(
        execution_intent_id=identity,
        incident_id=case.incident_id,
        expected_revision=record.revision,
        outcome=ReconciledOutcome.CONFIRMED_SUCCEEDED,
        reason="External verification",
        references=("synthetic-ticket",),
    )
    token = case.authority.confirm(
        subject="approver-bob",
        action=HumanAction.RECONCILE_EXECUTION,
        digest=content_digest(request),
    )
    case.executor.store.reconcile(request, credential=token, authority=case.authority)
    await finish(case)
    value = service.capture(case.incident_id)
    assert value.experience_id != uncertain.experience_id
    assert value.content.reconciliation == ReconciledOutcome.CONFIRMED_SUCCEEDED
    assert value.content.execution_outcome == HistoricalOutcome.SUCCEEDED
    assert (
        service.store.get(uncertain.experience_id).content.execution_outcome
        == HistoricalOutcome.UNCERTAIN
    )
    assert case.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_capture_has_no_mutation_issuance_or_execution(runtime_case, monkeypatch):
    from soc_agent.approval import ApprovalManager
    from soc_agent.execution import GovernedExecutor
    from soc_agent.execution.durable.service import DurableExecutor
    from soc_agent.response.promotion.service import PromotionService
    from soc_agent.review.service import HumanReviewService
    from soc_agent.tools.registry import ToolRegistry

    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    await finish(case)
    capture = capture_service(case)
    before = case.store.load(case.incident_id)

    def forbidden(*args, **kwargs):
        raise AssertionError("Capture attempted an authority/execution operation")

    for owner, methods in (
        (ApprovalManager, ("create", "approve")),
        (HumanReviewService, ("record_review", "authorize_change", "apply")),
        (PromotionService, ("record_review", "promote")),
        (GovernedExecutor, ("execute",)),
        (DurableExecutor, ("execute", "execute_claim")),
        (ToolRegistry, ("register",)),
        (SQLiteGovernanceStore, ("append_evidence",)),
    ):
        for method in methods:
            monkeypatch.setattr(owner, method, forbidden)
    value = capture.capture(case.incident_id)
    assert value.content.terminal
    assert case.store.load(case.incident_id) == before
    assert case.mocks["inspect_logs"].call_count == 1
    payload = value.model_dump_json()
    assert "Synthetic advisory analysis" not in payload
    assert "host_a" not in payload
    assert "reviewer-alice" not in payload


@pytest.mark.asyncio
async def test_policy_denied_execution_records_failure_without_invocation(runtime_case):
    from soc_agent.policy import PolicyDecision

    case = runtime_case(durable_workflow=True)
    await promoted_ready(case)
    case.policy.override = PolicyDecision.DENY
    await finish(case)
    value = capture_service(case).capture(case.incident_id)
    assert value.content.execution_outcome == HistoricalOutcome.FAILED
    assert value.content.failure == "execution_failed"
    assert case.mocks["inspect_logs"].call_count == 0
