"""Incident lifecycle through the existing runtime, never a parallel orchestrator."""

import pytest

from soc_agent.execution.durable import Lifecycle, ReconciledOutcome, ReconciliationRequest
from soc_agent.investigation.runtime import WorkflowFailure as Failure
from soc_agent.investigation.runtime import WorkflowStep as Step
from soc_agent.policy import PolicyDecision
from soc_agent.review import SeverityChange
from soc_agent.review.authority import HumanAction
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.identity import content_digest
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from soc_agent.tools.errors import ToolExecutionError
from tests.review_support import authorize
from tests.unit.investigation_runtime.conftest import decision_ready, review_for
from tests.unit.investigation_runtime.test_publication import analyzed, assessment
from tests.unit.promotion.conftest import approve

from .support import NETWORK_EVENT, ModelAnalysis, fusion_llm, promote_response


def assert_trace(case):
    trace = case.runtime.trace(case.incident_id)
    assert case.runtime.validate_trace(trace) == trace
    assert [e.content.sequence for e in trace.entries] == list(range(1, len(trace.entries) + 1))
    assert {e.content.result.incident_id for e in trace.entries} == {case.incident_id}
    assert {e.content.snapshot.incident_id for e in trace.entries} == {case.incident_id}
    return trace


@pytest.mark.asyncio
async def test_read_only_event_investigation_execution_complete(runtime_case):
    case = runtime_case(evidence=False)
    await promote_response(case)
    assert case.mocks["inspect_logs"].call_count == 1  # Investigation, not response.
    before = case.runtime.artifacts(case.incident_id)
    result = await case.runtime.advance(case.incident_id, execute=True)
    assert result.next_step == Step.EVALUATE
    assert (await case.runtime.advance(case.incident_id)).terminal
    trace = assert_trace(case)
    steps = [e.content.result.current_step for e in trace.entries]
    for step in (
        Step.OBSERVE,
        Step.PLAN,
        Step.ROUTE,
        Step.ANALYZE,
        Step.DECIDE,
        Step.GOVERN,
        Step.ACT,
        Step.EVALUATE,
    ):
        assert step in steps
    assert case.mocks["inspect_logs"].call_count == 2
    assert case.runtime.artifacts(case.incident_id).assessment == before.assessment
    state = case.store.load(case.incident_id).state
    assert len(state.evidence) == 1
    assert state.status == case.initial.status and state.severity == case.initial.severity


@pytest.mark.asyncio
async def test_ai_write_pause_resume_preserves_analysis_and_trace(runtime_case, monkeypatch):
    models = ModelAnalysis()
    case = runtime_case(event_fields=NETWORK_EVENT, model_analysis=models)
    llm = fusion_llm(case)
    await decision_ready(case)
    # Advisory concern requests additional investigation, driven by the runtime.
    assert (await case.runtime.advance(case.incident_id)).next_step == Step.ROUTE
    await case.runtime.advance(case.incident_id)
    await decision_ready(case)
    artifacts = case.runtime.artifacts(case.incident_id)
    assert len(models.runs) == llm.call_count == 2
    snapshot = case.store.load(case.incident_id)
    assert len(snapshot.state.evidence) == 2 and not snapshot.state.observations
    assert artifacts.decision.model_derived_context == models.runs[-1][2]
    assert len(models.runs[-1][2].signals) == 1
    assert models.runs[-1][2].signals[0].signal_id not in {
        e.evidence_id for e in snapshot.state.evidence
    }
    before = assert_trace(case)
    workflow, value, waiting = await promote_response(
        case, write=True, approve_write=False, analyze=False
    )
    assert waiting.waiting_for_human and waiting.next_step == Step.GOVERN
    assert case.mocks["test_response"].call_count == 0
    paused = assert_trace(case)
    assert paused.entries[: len(before.entries)] == before.entries
    for _ in range(3):
        await case.runtime.advance(case.incident_id, execute=True)
    assert case.runtime.trace(case.incident_id) == paused
    approval = approve(workflow, value)
    result = await case.runtime.advance(case.incident_id, approval_id=approval.approval_id)
    assert result.next_step == Step.ACT

    def forbidden(*args, **kwargs):
        pytest.fail("Runtime manufactured human authority")

    for obj, name in (
        (case.authority, "confirm"),
        (case.bridge, "approve_tool"),
        (case.bridge, "request_approval"),
        (case.approvals, "approve"),
        (case.promotion_service, "record_review"),
        (case.reviews, "record_review"),
    ):
        monkeypatch.setattr(obj, name, forbidden)
    assert (await case.runtime.advance(case.incident_id, execute=True)).next_step == Step.EVALUATE
    assert (await case.runtime.advance(case.incident_id)).terminal
    assert len(models.runs) == llm.call_count == 2
    assert case.mocks["test_response"].call_count == 1
    assert case.runtime.artifacts(case.incident_id).assessment == artifacts.assessment
    assert case.store.load(case.incident_id) == snapshot
    trace = assert_trace(case)
    assert trace.entries[: len(paused.entries)] == paused.entries
    refs = trace.entries[-1].content.result.references
    reference_map = {r.kind: r.identity for r in refs}
    assert reference_map["tool_approval"] == str(approval.approval_id)
    assert reference_map["promoted_action"] == value.promoted_id
    assert reference_map["response_plan"] == workflow[1].plan_id
    assert reference_map["decision"] == artifacts.decision.decision_id
    assert ("fusion", models.runs[-1][2].fusion_id) in {(r.kind, r.identity) for r in refs}


@pytest.mark.asyncio
@pytest.mark.parametrize("uncertain", [False, True])
async def test_outcome_and_trusted_reconciliation_lifecycle(runtime_case, uncertain):
    error = TimeoutError("Remote reply unavailable") if uncertain else ToolExecutionError("Failed")
    case = runtime_case(evidence=False, responses=[{"result": "source record"}, error])
    await promote_response(case)
    outcome = await case.runtime.advance(case.incident_id, execute=True)
    identity = case.runtime.artifacts(case.incident_id).execution_intent_id
    record = case.executor.store.load(identity)
    if not uncertain:
        assert record.state == Lifecycle.FAILED
        assert outcome.failure == Failure.EXECUTION
        assert (await case.runtime.advance(case.incident_id)).terminal
    else:
        assert outcome.next_step == Step.RECOVER and record.state == Lifecycle.UNCERTAIN
        for _ in range(3):
            result = await case.runtime.advance(case.incident_id, execute=True)
            assert result.waiting_for_human and not result.terminal
        request = ReconciliationRequest(
            execution_intent_id=identity,
            incident_id=case.incident_id,
            expected_revision=record.revision,
            outcome=ReconciledOutcome.CONFIRMED_SUCCEEDED,
            reason="Operator verified outcome externally",
            references=("verification-ticket",),
        )
        with pytest.raises(HumanAuthorizationDenied):
            case.executor.store.reconcile(request, credential="caller-string")
        assert case.executor.store.load(identity).state == Lifecycle.UNCERTAIN
        token = case.authority.confirm(
            subject="approver-bob",
            action=HumanAction.RECONCILE_EXECUTION,
            digest=content_digest(request),
        )
        case.executor.store.reconcile(request, credential=token, authority=case.authority)
        assert (await case.runtime.advance(case.incident_id)).next_step == Step.EVALUATE
        assert (await case.runtime.advance(case.incident_id)).terminal
    await case.runtime.advance(case.incident_id, execute=True)
    assert case.mocks["inspect_logs"].call_count == 2
    assert_trace(case)


@pytest.mark.asyncio
async def test_policy_deny_after_write_approval_prevents_execution(runtime_case):
    case = runtime_case(severities=("high",))
    await promote_response(case, write=True)
    case.policy.override = PolicyDecision.DENY
    outcome = await case.runtime.advance(case.incident_id, execute=True)
    assert outcome.failure == Failure.GOVERNANCE and outcome.terminal
    assert case.mocks["test_response"].call_count == 0
    assert_trace(case)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["state", "input", "state_authorization"])
async def test_exact_write_approval_boundary(runtime_case, change):
    case = runtime_case(severities=("high",))
    workflow, value, _ = await promote_response(case, write=True, approve_write=False)
    approval = approve(workflow, value)
    if change == "state":
        snapshot = case.store.load(case.incident_id)
        case.store.append_evidence(
            snapshot.anchor,
            Evidence(
                incident_id=case.incident_id,
                source="external",
                summary="New evidence",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
        result = await case.runtime.advance(case.incident_id, approval_id=approval.approval_id)
    elif change == "input":
        request = value.content.request
        target = request.target
        proposal = target.proposal
        intent = proposal.details.intent.model_copy(update={"proposed_input": '{"target":"other"}'})
        proposal = proposal.model_copy(
            update={"details": proposal.details.model_copy(update={"intent": intent})}
        )
        target = target.model_copy(update={"proposal": proposal})
        forged = value.model_copy(
            update={
                "content": value.content.model_copy(
                    update={"request": request.model_copy(update={"target": target})}
                )
            }
        )
        result = await case.runtime.advance(
            case.incident_id, promoted=forged, approval_id=approval.approval_id
        )
    else:
        review = workflow[1].content.basis.review
        request = case.reviews.propose_change(
            review,
            changes=(SeverityChange(before="info", after="medium"),),
            reason="State-only authorization",
        )
        authorization = authorize(case.reviews, case.authority, request, review)
        result = await case.runtime.advance(
            case.incident_id, approval_id=authorization.authorization_id
        )
    assert result.failure == Failure.VALIDATION
    assert case.mocks["test_response"].call_count == 0
    assert_trace(case)


@pytest.mark.asyncio
async def test_cross_incident_review_is_rejected_without_losing_work(runtime_case):
    a, b = runtime_case(), runtime_case()
    await decision_ready(a)
    await decision_ready(b)
    before = a.runtime.artifacts(a.incident_id)
    result = await a.runtime.advance(a.incident_id, review=review_for(b))
    assert result.failure == Failure.VALIDATION
    assert a.runtime.artifacts(a.incident_id) == before
    await promote_response(a, analyze=False)
    await a.runtime.advance(a.incident_id, execute=True)
    assert (await a.runtime.advance(a.incident_id)).terminal
    assert_trace(a)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value", [("status", "closed"), ("severity", "critical"), ("evidence", ())]
)
async def test_e2e_analysis_cannot_mutate_protected_state(runtime_case, field, value):
    case = runtime_case()
    before = case.store.load(case.incident_id)
    valid = assessment(analyzed(before.state))
    forged = valid.model_copy(
        update={"incident_state": valid.incident_state.model_copy(update={field: value})}
    )

    async def assess(*args, **kwargs):
        return forged

    # Replace only the untrusted analysis boundary; publication still uses the real store.
    case.runtime._assessor.assess = assess
    await case.runtime.advance(case.incident_id)
    await case.runtime.advance(case.incident_id)
    result = await case.runtime.advance(case.incident_id)
    assert result.failure == Failure.ANALYSIS and result.terminal
    assert case.store.load(case.incident_id) == before
    assert_trace(case)
