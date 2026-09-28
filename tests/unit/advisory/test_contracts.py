from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.unit.advisory.conftest import create
from tests.unit.execution.conftest import make_tool

from soc_agent.execution import ActionProposal as ExecutableAction
from soc_agent.policy import PolicyDecision
from soc_agent.response.advisory import ActionProposal, CandidateIntent, ResponsePlan
from soc_agent.tools import ToolPermission, ToolRiskLevel


def test_grounding_and_no_mutation(planning):
    state, decision, review, store, service, registry, planner, candidate, _ = planning
    before = state.model_dump_json(), store.events(), service.authorizations(), registry.list()
    plan = create(planning)
    planner.validate_current(plan, incident_state=state)
    assert plan.content.basis.decision == decision
    assert plan.content.basis.review == review
    assert plan.content.basis.snapshot == store.load(state.incident_id).anchor
    assert plan.content.basis.evidence == state.evidence
    assert plan.content.evidence_ids == candidate.evidence_ids
    assert plan.proposed_actions[0].details.category == "additional_investigation"
    assert plan.proposed_actions[0].details.reversibility == "unknown"
    assert plan.proposed_actions[0].details.policy_preflight.decision == PolicyDecision.ALLOW
    assert before == (
        state.model_dump_json(),
        store.events(),
        service.authorizations(),
        registry.list(),
    )


@pytest.mark.parametrize("member", ["plan", "proposal", "intent", "metadata", "policy"])
def test_deep_immutable(planning, member):
    plan = create(planning)
    action = plan.proposed_actions[0]
    obj = {
        "plan": plan,
        "proposal": action,
        "intent": action.details.intent,
        "metadata": action.details.metadata,
        "policy": action.details.policy_preflight,
    }[member]
    with pytest.raises(ValidationError):
        setattr(obj, next(iter(type(obj).model_fields)), "changed")


def test_identity_order_and_clocks(planning):
    candidate = planning[7]
    second = candidate.model_copy(update={"rationale": "Second alternative"})
    first = create(planning, (candidate, second))
    reordered = create(planning, (second, candidate, candidate))
    assert first.plan_id == reordered.plan_id
    assert first.proposed_actions == reordered.proposed_actions
    assert first.created_at != reordered.created_at
    changed_clock = first.model_dump() | {"created_at": first.created_at + timedelta(days=1)}
    assert ResponsePlan.model_validate(changed_clock).plan_id == first.plan_id


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "Other purpose"),
        ("rationale", "Other reason"),
        ("proposed_input", '{"target":"host_b"}'),
    ],
)
def test_semantic_changes_change_identity(planning, field, value):
    original = create(planning)
    changed = create(planning, (planning[7].model_copy(update={field: value}),))
    assert changed.plan_id != original.plan_id
    assert changed.proposed_actions[0].proposal_id != original.proposed_actions[0].proposal_id


@pytest.mark.parametrize("change", ["input", "permission", "risk", "policy", "plan", "evidence"])
def test_tampered_proposal_rejected(planning, change):
    action = create(planning).proposed_actions[0]
    data = action.model_dump(mode="json")
    if change == "input":
        data["details"]["intent"]["proposed_input"] = '{"target":"other"}'
    elif change in ("permission", "risk"):
        data["details"]["metadata"]["permission" if change == "permission" else "risk_level"] = (
            "network_write" if change == "permission" else "high"
        )
    elif change == "policy":
        data["details"]["policy_preflight"]["decision"] = "deny"
    elif change == "plan":
        data["response_plan_id"] = "0" * 64
    else:
        data["details"]["intent"]["evidence_ids"] = [str(uuid4())]
    with pytest.raises(ValueError):
        ActionProposal.model_validate(data)


def test_plan_tampering_and_execution_incompatibility(planning):
    plan = create(planning)
    data = plan.model_dump()
    data["content"]["objective"] = "Modified purpose"
    with pytest.raises(ValueError):
        ResponsePlan.model_validate(data)
    for artifact in (plan, plan.proposed_actions[0]):
        with pytest.raises(ValidationError):
            ExecutableAction.model_validate(artifact.model_dump())


@pytest.mark.parametrize("raw", [{"target": 123}, {"target": "host", "extra": True}, {}])
def test_exact_schema_required(planning, raw):
    candidate = CandidateIntent.model_validate(planning[7].model_dump() | {"proposed_input": raw})
    with pytest.raises(ValueError):
        create(planning, (candidate,))


def test_non_evidence_rejected(planning):
    # UUID shape is never evidence membership, regardless of claimed identifier origin.
    candidate = planning[7].model_copy(update={"evidence_ids": (uuid4(),)})
    with pytest.raises(ValueError, match="Evidence"):
        create(planning, (candidate,))


def test_unknown_tool_rejected(planning):
    candidate = planning[7].model_copy(update={"candidate_tool": "isolate_host"})
    with pytest.raises(ValueError, match="Registry"):
        create(planning, (candidate,))


@pytest.mark.parametrize(
    "name,decision",
    [("test_response", PolicyDecision.REQUIRE_APPROVAL), ("test_destructive", PolicyDecision.DENY)],
)
def test_write_policy_preserved(planning, name, decision):
    plan = create(planning, (planning[7].model_copy(update={"candidate_tool": name}),))
    action = plan.proposed_actions[0]
    assert action.details.category == "response_consideration"
    assert action.details.policy_preflight.decision == decision
    assert action.details.human_approval_required == (decision == PolicyDecision.REQUIRE_APPROVAL)
    assert action.details.blocking_reasons
    assert action.details.expected_operational_impact
    assert planning[4].authorizations() == ()


def test_tool_binding_change_requires_revalidation(planning):
    plan = create(planning)
    state, _, _, _, _, registry, planner, _, _ = planning
    # Simulate a trusted deployment changing registry metadata after proposal creation.
    registry._tools["inspect_logs"] = make_tool(
        ToolPermission.NETWORK_READ, ToolRiskLevel.HIGH, "inspect_logs"
    ).tool
    with pytest.raises(ValueError, match="Stale"):
        planner.validate_current(plan, incident_state=state)


@pytest.mark.parametrize(
    "permission,risk,expected",
    [
        (ToolPermission.NETWORK_WRITE, ToolRiskLevel.LOW, PolicyDecision.REQUIRE_APPROVAL),
        (ToolPermission.NETWORK_WRITE, ToolRiskLevel.READ_ONLY, PolicyDecision.DENY),
        (ToolPermission.NETWORK_READ, ToolRiskLevel.HIGH, PolicyDecision.REQUIRE_APPROVAL),
    ],
)
def test_additional_policy_cases(planning, permission, risk, expected):
    planning[5].register(make_tool(permission, risk, "policy_candidate").tool)
    candidate = planning[7].model_copy(update={"candidate_tool": "policy_candidate"})
    proposal = create(planning, (candidate,)).proposed_actions[0]
    assert proposal.details.policy_preflight.decision == expected
    assert proposal.details.metadata.permission == permission
    assert proposal.details.metadata.risk_level == risk


def test_input_object_order_is_not_semantic():
    data = dict(
        candidate_tool="inspect_logs",
        purpose="Inspect",
        rationale="Verify",
        proposed_input={"first": 1, "second": 2},
    )
    left = CandidateIntent(**data)
    right = CandidateIntent(**(data | {"proposed_input": {"second": 2, "first": 1}}))
    assert left == right


def test_missing_candidate_grounding_is_explicit(planning):
    candidate = planning[7].model_copy(update={"evidence_ids": ()})
    proposal = create(planning, (candidate,)).proposed_actions[0]
    assert any("no linked Evidence" in reason for reason in proposal.details.blocking_reasons)


def test_schema_change_invalidates_proposal(planning):
    from pydantic import BaseModel

    from soc_agent.tools import Tool

    plan = create(planning)
    old = planning[5].get("inspect_logs")

    class NewInput(BaseModel):
        target: str
        limit: int = 10

    planning[5]._tools["inspect_logs"] = Tool(
        metadata=old.metadata,
        input_model=NewInput,
        output_model=old.output_model,
        handler=old.handler,
    )
    with pytest.raises(ValueError, match="Stale"):
        planning[6].validate_current(plan, incident_state=planning[0])
