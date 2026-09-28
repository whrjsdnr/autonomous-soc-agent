from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.review_support import record_review
from tests.unit.advisory.conftest import create

from soc_agent.approval import ApprovalManager
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.execution import GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.response.advisory import PersistentPlanningSource, ResponsePlanner
from soc_agent.review import HumanReviewService, ReviewOutcome
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.review.persistence.session import GovernanceSession
from soc_agent.state import Evidence, IncidentStatus
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolRegistry


@pytest.mark.parametrize("outcome", list(ReviewOutcome))
def test_review_disposition(planning, outcome):
    state, decision, _, store, service, registry, planner, candidate, authority = planning
    review = record_review(service, authority, service.request_review(state, decision), outcome)
    plan = create(
        planning,
        (candidate, candidate.model_copy(update={"candidate_tool": "test_response"})),
        review=review,
    )
    actions = plan.proposed_actions
    if outcome == ReviewOutcome.REJECTED:
        assert actions == ()
        assert (
            "review_rejected_state_change_conservative_planning_stop" in plan.content.dispositions
        )
    elif outcome == ReviewOutcome.INVESTIGATE:
        assert len(actions) == 1
        assert actions[0].details.category == "additional_investigation"
        assert "response_candidate_deferred_for_investigation" in plan.content.dispositions
    else:
        assert len(actions) == 2
    assert service.authorizations() == store.applications() == ()
    planner.validate_current(plan, incident_state=state)


def test_no_response_capability(planning):
    registry = ToolRegistry()
    registry.register(planning[5].get("inspect_logs"))
    planner = ResponsePlanner(registry=registry, source=PersistentPlanningSource(planning[3]))
    plan = planner.create_plan(
        incident_state=planning[0],
        decision=planning[1],
        review=planning[2],
        objective="Additional investigation",
        candidates=(planning[7],),
    )
    assert "appropriate_response_tool_unavailable" in plan.content.dispositions
    assert plan.proposed_actions[0].details.category == "additional_investigation"


def test_empty_registry_returns_no_invented_tool(planning):
    planner = ResponsePlanner(registry=ToolRegistry(), source=PersistentPlanningSource(planning[3]))
    plan = planner.create_plan(
        incident_state=planning[0],
        decision=planning[1],
        review=planning[2],
        objective="Consider options",
    )
    assert plan.proposed_actions == ()
    assert "appropriate_response_tool_unavailable" in plan.content.dispositions


def test_closed_refused(planning):
    with pytest.raises(ValueError, match="CLOSED"):
        create(
            planning,
            incident_state=planning[0].model_copy(update={"status": IncidentStatus.CLOSED}),
        )


@pytest.mark.parametrize("part", ["incident", "decision", "review", "snapshot", "review_reason"])
def test_source_binding_rejects_unregistered_or_changed(planning, part):
    state, decision, review, *_ = planning
    updates = {}
    if part == "incident":
        updates["incident_state"] = state.model_copy(update={"incident_id": uuid4()})
    elif part == "decision":
        updates["decision"] = decision.model_copy(update={"decision_id": "0" * 64})
    elif part == "review":
        updates["review"] = review.model_copy(update={"review_id": uuid4()})
    elif part == "review_reason":
        updates["review"] = review.model_copy(update={"reason": "Changed disposition explanation"})
    else:
        anchor = review.target.snapshot.model_copy(update={"revision": 99})
        target = review.target.model_copy(update={"snapshot": anchor})
        updates["review"] = review.model_copy(update={"target": target})
    with pytest.raises(ValueError):
        create(planning, **updates)


def test_stale_after_new_evidence(planning):
    state, _, review, store, _, _, planner, _, _ = planning
    plan = create(planning)
    later = store.append_evidence(
        review.target.snapshot,
        Evidence(
            incident_id=state.incident_id,
            source="later",
            summary="New evidence",
            raw_data="{}",
            observed_at=utc_now(),
        ),
    )
    for current in (state, later.state):
        with pytest.raises(ValueError):
            planner.validate_current(plan, incident_state=current)


def test_foreign_incident_evidence_rejected(planning):
    evidence = Evidence(
        incident_id=uuid4(),
        source="other",
        summary="Other incident",
        raw_data="{}",
        observed_at=utc_now(),
    )
    with pytest.raises(ValueError, match="Evidence"):
        create(
            planning, (planning[7].model_copy(update={"evidence_ids": (evidence.evidence_id,)}),)
        )


def test_no_automatic_operations(planning, monkeypatch):
    store = planning[3]
    before = store.load(planning[0].incident_id), store.events()

    def forbidden(*args, **kwargs):
        pytest.fail("Planning crossed the no-execution boundary")

    for cls, method in (
        (GovernedExecutor, "execute"),
        (GovernedExecutor, "request_approval"),
        (Tool, "execute"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (HumanReviewService, "record_review"),
        (HumanReviewService, "authorize_change"),
        (PersistentHumanReviewService, "authorize_change"),
        (PersistentHumanReviewService, "apply"),
        (SQLiteGovernanceStore, "compare_and_apply"),
        (GovernanceSession, "save_state"),
        (ToolRegistry, "register"),
        (IncidentDecisionEngine, "decide"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    plan = create(planning)
    planning[6].validate_current(plan, incident_state=planning[0])
    assert before == (store.load(planning[0].incident_id), store.events())


@pytest.mark.asyncio
async def test_executor_rejects_advisory_object_before_execution(planning, monkeypatch):
    plan = create(planning)
    executor = GovernedExecutor(
        registry=planning[5], policy=PolicyEngine(), approvals=ApprovalManager()
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Advisory object reached Tool execution")

    monkeypatch.setattr(Tool, "execute", forbidden)
    for artifact in (plan, plan.proposed_actions[0]):
        with pytest.raises(ValidationError):
            await executor.execute(artifact)
        with pytest.raises(ValidationError):
            executor.request_approval(artifact, reason="Must not issue")


@pytest.mark.asyncio
async def test_legacy_coordinator_rejects_advisory_plan(planning, monkeypatch):
    from soc_agent.response import ResponseCoordinator
    from soc_agent.response.models import ResponsePlan as ExecutablePlan

    plan = create(planning)
    executor = GovernedExecutor(
        registry=planning[5], policy=PolicyEngine(), approvals=ApprovalManager()
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Legacy workflow forwarded an advisory plan for execution")

    monkeypatch.setattr(GovernedExecutor, "execute", forbidden)
    monkeypatch.setattr(Tool, "execute", forbidden)
    monkeypatch.setattr(ApprovalManager, "create", forbidden)
    with pytest.raises(ValidationError):
        ExecutablePlan.model_validate(plan.model_dump())
    # The legacy coordinator requires its step-lifecycle contract. Advisory plans
    # deliberately provide neither that interface nor an automatic converter.
    with pytest.raises(AttributeError):
        await ResponseCoordinator(executor=executor).execute_plan(
            incident_state=planning[0], plan=plan
        )
