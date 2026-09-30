import asyncio
from uuid import uuid4

import pytest
from tests.unit.promotion.conftest import approve

from soc_agent.execution.durable import Lifecycle, ReconciledOutcome, ReconciliationRequest
from soc_agent.investigation.runtime import WorkflowFailure as Failure
from soc_agent.investigation.runtime import WorkflowStep as Step
from soc_agent.policy import PolicyDecision
from soc_agent.review import ReviewOutcome
from soc_agent.review.authority import HumanAction
from soc_agent.review.identity import content_digest
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from soc_agent.tools.errors import ToolExecutionError

from .conftest import decision_ready, promoted_ready, review_for


@pytest.mark.asyncio
async def test_normal_routing_and_artifacts_survive_pause(runtime_case):
    c = runtime_case()
    steps = [await c.runtime.advance(c.incident_id) for _ in range(4)]
    assert [(r.current_step, r.next_step) for r in steps] == [
        (Step.OBSERVE, Step.ROUTE),
        (Step.ROUTE, Step.ANALYZE),
        (Step.ANALYZE, Step.DECIDE),
        (Step.DECIDE, Step.GOVERN),
    ]
    before = c.runtime.artifacts(c.incident_id)
    assert before.assessment.incident_state == c.store.load(c.incident_id).state
    assert len(before.assessment.incident_state.observations) == 1
    for _ in range(3):
        result = await c.runtime.advance(c.incident_id)
        assert result.waiting_for_human and not result.terminal
        assert result.incident_id == c.incident_id and len(result.references) == 2
    assert c.runtime.artifacts(c.incident_id) == before
    assert c.llm.calls == 1
    assert c.mocks["inspect_logs"].call_count == 0
    assert c.store.load(c.incident_id).state.severity == c.initial.severity
    assert [e.event_type for e in c.store.events()] == [
        "incident_registered",
        "assessment_appended",
    ]
    review = review_for(c)
    resumed = await c.runtime.advance(c.incident_id, review=review)
    assert resumed.current_step == resumed.next_step == Step.GOVERN
    assert c.runtime.artifacts(c.incident_id).assessment == before.assessment
    no_candidates = await c.runtime.advance(c.incident_id)
    assert no_candidates.waiting_for_human
    assert c.runtime.artifacts(c.incident_id).response_plan is None


@pytest.mark.asyncio
async def test_insufficient_evidence_collects_using_existing_orchestrator(runtime_case):
    c = runtime_case(evidence=False)
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.PLAN
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.ROUTE
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.ROUTE
    state = c.store.load(c.incident_id).state
    assert len(state.evidence) == 1 and state.evidence[0].source == "tool:inspect_logs"
    assert c.mocks["inspect_logs"].call_count == 1
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.ANALYZE


@pytest.mark.asyncio
async def test_additional_investigation_loops_then_reassesses(runtime_case):
    c = runtime_case(severities=("high", "info"))
    assert (await decision_ready(c)).next_step == Step.PLAN
    first = c.runtime.artifacts(c.incident_id).assessment
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.ROUTE
    await c.runtime.advance(c.incident_id)
    assert c.runtime.artifacts(c.incident_id).assessment is None
    assert (await decision_ready(c)).next_step == Step.GOVERN
    assert len(c.store.load(c.incident_id).state.observations) == 2
    assert c.runtime.artifacts(c.incident_id).assessment != first
    assert c.llm.calls == 2


@pytest.mark.asyncio
async def test_valid_human_investigate_returns_to_plan(runtime_case):
    c = runtime_case(severities=("info", "info"))
    await decision_ready(c)
    result = await c.runtime.advance(c.incident_id, review=review_for(c, ReviewOutcome.INVESTIGATE))
    assert result.next_step == Step.PLAN and c.planner_llm.call_count == 0
    assert (await c.runtime.advance(c.incident_id)).next_step == Step.ROUTE
    await c.runtime.advance(c.incident_id)
    assert (await decision_ready(c)).next_step == Step.GOVERN
    assert (await c.runtime.advance(c.incident_id)).waiting_for_human


@pytest.mark.asyncio
async def test_write_pauses_then_approved_existing_durable_execution(runtime_case):
    c = runtime_case(severities=("high",))
    value, workflow, result = await promoted_ready(c, write=True, approval=False)
    assert result.next_step == Step.GOVERN and result.waiting_for_human
    assert c.mocks["test_response"].call_count == 0
    approved = approve(workflow, value)
    result = await c.runtime.advance(c.incident_id, approval_id=approved.approval_id, execute=True)
    assert result.next_step == Step.ACT and c.mocks["test_response"].call_count == 0
    assert (await c.runtime.advance(c.incident_id)).waiting_for_human
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.EVALUATE
    identity = c.runtime.artifacts(c.incident_id).execution_intent_id
    assert c.executor.store.load(identity).state == Lifecycle.SUCCEEDED
    final = await c.runtime.advance(c.incident_id)
    assert final.terminal and final.failure is None
    await c.runtime.advance(c.incident_id, execute=True)
    assert c.mocks["test_response"].call_count == 1


@pytest.mark.asyncio
async def test_policy_deny_at_dispatch_fails_closed(runtime_case):
    c = runtime_case(severities=("high",))
    await promoted_ready(c, write=True)
    c.policy.override = PolicyDecision.DENY
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.terminal and result.failure == Failure.GOVERNANCE
    assert c.mocks["test_response"].call_count == 0
    assert c.runtime.artifacts(c.incident_id).execution_intent_id is None


@pytest.mark.asyncio
async def test_failed_execution_has_explicit_failure_result(runtime_case):
    c = runtime_case(responses=[ToolExecutionError("Adapter reports failure")])
    await promoted_ready(c)
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.EVALUATE and result.failure == Failure.EXECUTION
    final = await c.runtime.advance(c.incident_id)
    assert final.terminal and final.failure == Failure.EXECUTION
    assert (await c.runtime.advance(c.incident_id)).failure == Failure.EXECUTION
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_uncertain_no_retry_and_external_reconciliation(runtime_case):
    c = runtime_case(responses=[TimeoutError("Lost reply")])
    await promoted_ready(c)
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.RECOVER and result.failure == Failure.UNCERTAIN
    identity = c.runtime.artifacts(c.incident_id).execution_intent_id
    for _ in range(3):
        result = await c.runtime.advance(c.incident_id, execute=True)
        assert result.next_step == Step.RECOVER and result.waiting_for_human
    assert c.mocks["inspect_logs"].call_count == 1
    record = c.executor.store.load(identity)
    request = ReconciliationRequest(
        execution_intent_id=identity,
        incident_id=c.incident_id,
        expected_revision=record.revision,
        outcome=ReconciledOutcome.CONFIRMED_FAILED,
        reason="External human verified failure",
        references=("operator-ticket",),
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
@pytest.mark.parametrize("repeated", [False, True])
async def test_deterministic_loop_guard_requires_human_artifact(runtime_case, repeated):
    c = runtime_case(
        severities=("high", "high", "high"), limit=2 if repeated else 1, plans=("host_a", "host_a")
    )
    await decision_ready(c)
    await c.runtime.advance(c.incident_id)
    await c.runtime.advance(c.incident_id)
    await decision_ready(c)
    before = c.runtime.artifacts(c.incident_id)
    result = await c.runtime.advance(c.incident_id)
    assert result.next_step == Step.PLAN and result.failure == Failure.LOOP_GUARD
    count = c.planner_llm.call_count
    for _ in range(3):
        result = await c.runtime.advance(c.incident_id)
        assert result.waiting_for_human and result.failure == Failure.LOOP_GUARD
    assert c.planner_llm.call_count == count and c.mocks["inspect_logs"].call_count == 1
    assert c.runtime.artifacts(c.incident_id) == before
    result = await c.runtime.advance(c.incident_id, review=review_for(c))
    assert result.next_step == Step.GOVERN
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_forged_review_rejected_and_input_bundle_is_atomic(runtime_case):
    c = runtime_case()
    await decision_ready(c)
    review = review_for(c)
    result = await c.runtime.advance(
        c.incident_id, review=review.model_copy(update={"review_id": uuid4()})
    )
    assert result.failure == Failure.VALIDATION
    result = await c.runtime.advance(c.incident_id, review=review, approval_id=uuid4())
    assert result.failure == Failure.VALIDATION
    assert "incident_review" not in {r.kind for r in result.references}
    assert (await c.runtime.advance(c.incident_id, review=review)).failure is None


@pytest.mark.asyncio
async def test_stale_state_pauses_preserving_analysis(runtime_case):
    c = runtime_case()
    await decision_ready(c)
    before = c.runtime.artifacts(c.incident_id)
    c.store.append_evidence(
        before.snapshot,
        Evidence(
            incident_id=c.incident_id,
            source="external",
            summary="New source record",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    result = await c.runtime.advance(c.incident_id)
    assert result.waiting_for_human and result.failure == Failure.VALIDATION
    assert c.runtime.artifacts(c.incident_id) == before


@pytest.mark.asyncio
async def test_ambiguous_create_commit_queries_without_dispatch(runtime_case, monkeypatch):
    c = runtime_case()
    await promoted_ready(c)
    create = c.executor.store.create

    def lost_reply(*args, **kwargs):
        create(*args, **kwargs)
        raise OSError("Commit reply unavailable")

    monkeypatch.setattr(c.executor.store, "create", lost_reply)
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.RECOVER
    assert c.runtime.artifacts(c.incident_id).execution_intent_id is not None
    await c.runtime.advance(c.incident_id, execute=True)
    assert c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
async def test_cancelled_dispatch_retains_recovery_cursor(runtime_case, monkeypatch):
    c = runtime_case()
    await promoted_ready(c)

    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(c.executor, "execute", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await c.runtime.advance(c.incident_id, execute=True)
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.RECOVER
    assert c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
async def test_rejected_review_completes_without_action(runtime_case):
    c = runtime_case()
    await decision_ready(c)
    await c.runtime.advance(c.incident_id, review=review_for(c, ReviewOutcome.REJECTED))
    result = await c.runtime.advance(c.incident_id)
    assert result.terminal and result.failure == Failure.GOVERNANCE
    assert c.mocks["inspect_logs"].call_count == 0


@pytest.mark.asyncio
async def test_review_for_other_registered_decision_is_not_accepted(runtime_case):
    from tests.review_support import record_review

    from soc_agent.decision import IncidentDecisionEngine

    c = runtime_case()
    await decision_ready(c)
    artifacts = c.runtime.artifacts(c.incident_id)
    state = c.store.load(c.incident_id).state
    other_assessment = artifacts.assessment.threat_assessment.model_copy(
        update={"assessment_id": uuid4(), "summary": "Another interpretation"}
    )
    other_decision = IncidentDecisionEngine().decide(state, other_assessment)
    review = record_review(c.reviews, c.authority, c.reviews.request_review(state, other_decision))
    # Register the correct decision too, to exercise exact review-to-decision binding
    # rather than merely rejection of an unknown decision.
    c.reviews.request_review(state, artifacts.decision)
    result = await c.runtime.advance(c.incident_id, review=review)
    assert result.failure == Failure.VALIDATION
    assert "incident_review" not in {r.kind for r in result.references}


@pytest.mark.asyncio
async def test_policy_denied_investigation_does_not_call_tool(runtime_case):
    c = runtime_case(evidence=False)
    await c.runtime.advance(c.incident_id)
    await c.runtime.advance(c.incident_id)
    c.policy.override = PolicyDecision.DENY
    result = await c.runtime.advance(c.incident_id)
    assert result.terminal and result.failure == Failure.INVESTIGATION
    assert c.mocks["inspect_logs"].call_count == 0
    assert not c.store.load(c.incident_id).state.evidence


@pytest.mark.asyncio
async def test_failed_analysis_is_terminal_and_not_retried(runtime_case):
    c = runtime_case(severities=())
    await c.runtime.advance(c.incident_id)
    await c.runtime.advance(c.incident_id)
    result = await c.runtime.advance(c.incident_id)
    assert result.terminal and result.failure == Failure.ANALYSIS
    await c.runtime.advance(c.incident_id)
    assert c.llm.calls == 1
    assert c.store.load(c.incident_id).state == c.initial


@pytest.mark.asyncio
async def test_concurrent_explicit_dispatch_invokes_once(runtime_case):
    c = runtime_case()
    await promoted_ready(c)
    results = await asyncio.gather(
        *(c.runtime.advance(c.incident_id, execute=True) for _ in range(3))
    )
    assert [r.next_step for r in results] == [Step.EVALUATE, Step.COMPLETE, Step.COMPLETE]
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_existing_succeeded_intent_is_inspected_not_reexecuted(runtime_case):
    c = runtime_case()
    value, _, _ = await promoted_ready(c)
    record = c.executor.store.create(c.bridge, value)
    await c.executor.execute(record.intent.execution_intent_id, claimant="external-caller")
    assert (await c.runtime.advance(c.incident_id, execute=True)).next_step == Step.EVALUATE
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_recovery_query_survives_external_incident_change(runtime_case):
    c = runtime_case(responses=[TimeoutError("Lost reply")])
    await promoted_ready(c)
    await c.runtime.advance(c.incident_id, execute=True)
    snapshot = c.store.load(c.incident_id)
    c.store.append_evidence(
        snapshot.anchor,
        Evidence(
            incident_id=c.incident_id,
            source="external",
            summary="Reconciliation source",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    result = await c.runtime.advance(c.incident_id, execute=True)
    assert result.next_step == Step.RECOVER and result.failure == Failure.UNCERTAIN
    assert c.mocks["inspect_logs"].call_count == 1


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_budget_must_be_positive_finite_integer(runtime_case, limit):
    with pytest.raises(ValueError, match="positive finite"):
        runtime_case(limit=limit)


@pytest.mark.asyncio
async def test_model_adapter_routes_fusion_to_existing_assessor(runtime_case):
    from soc_agent.assessment import FusionAssessmentResult
    from soc_agent.llm import MockLLMClient
    from soc_agent.security_ai.fusion import MultiModelFusionEngine

    calls = []

    async def model_analysis(state):
        calls.append(state.incident_id)
        return MultiModelFusionEngine((), ("network_classifier",)).fuse(
            incident_id=state.incident_id, inputs=()
        )

    c = runtime_case(model_analysis=model_analysis)
    c.llm.generate_structured = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.2,
                    "summary": "Coverage unavailable, not proof of safety",
                    "supporting_evidence_ids": [str(c.initial.evidence[0].evidence_id)],
                },
            }
        ]
    ).generate_structured
    await decision_ready(c)
    artifacts = c.runtime.artifacts(c.incident_id)
    assert calls == [c.incident_id]
    assert isinstance(artifacts.assessment, FusionAssessmentResult)
    assert artifacts.decision.model_derived_context == artifacts.assessment.model_derived_context
    assert c.store.load(c.incident_id).state == c.initial
    assert artifacts.decision.additional_investigation_required


@pytest.mark.asyncio
async def test_runtime_never_issues_human_authority(runtime_case, monkeypatch):
    c = runtime_case()

    def forbidden(*args, **kwargs):
        pytest.fail("Runtime attempted to manufacture human authority")

    for obj, method in (
        (c.reviews, "request_review"),
        (c.reviews, "record_review"),
        (c.promotion_service, "request_review"),
        (c.promotion_service, "record_review"),
        (c.promotion_service, "promote"),
        (c.bridge, "request_approval"),
        (c.bridge, "approve_tool"),
        (c.authority, "confirm"),
        (c.approvals, "approve"),
        (c.store, "compare_and_apply"),
    ):
        monkeypatch.setattr(obj, method, forbidden)
    await decision_ready(c)
    result = await c.runtime.advance(c.incident_id)
    assert result.waiting_for_human
    assert c.mocks["inspect_logs"].call_count == 0
