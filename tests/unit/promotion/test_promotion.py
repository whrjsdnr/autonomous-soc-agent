from uuid import uuid4

import pytest
from pydantic import ValidationError
from tests.unit.promotion.conftest import reviewed

from soc_agent.policy import PolicyDecision
from soc_agent.response.promotion import PromotionService, ReviewDisposition
from soc_agent.response.promotion.errors import (
    IncidentClosed,
    InputSchemaChanged,
    InvalidPromotionArtifact,
    PromotionPolicyChanged,
    PromotionPolicyDenied,
    PromotionToolMissing,
    ResponseChangesRequested,
    ResponseReviewRejected,
    ToolMetadataChanged,
)
from soc_agent.review import HumanAuthorizationDenied
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.state import Evidence
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool


def test_exact_stable_promotion_no_approval(workflow):
    review = reviewed(workflow)
    service = workflow[3]
    request = service.request_promotion(review)
    first = service.promote(request)
    assert first == service.promote(request)
    assert first.content.request.review == review
    assert first.content.current_snapshot == workflow[1].content.basis.snapshot
    assert first.content.current_policy.decision == PolicyDecision.ALLOW
    assert workflow[4].list() == ()
    assert workflow[5].audit_events() == ()


@pytest.mark.parametrize("kind", ["review", "request", "promoted"])
def test_immutable(workflow, kind):
    review = reviewed(workflow)
    request = workflow[3].request_promotion(review)
    value = {"review": review, "request": request, "promoted": workflow[3].promote(request)}[kind]
    with pytest.raises(ValidationError):
        setattr(value, next(iter(type(value).model_fields)), "changed")


@pytest.mark.parametrize(
    "disposition,error",
    [
        (ReviewDisposition.REJECT, ResponseReviewRejected),
        (ReviewDisposition.REQUEST_CHANGES, ResponseChangesRequested),
    ],
)
def test_human_disposition(workflow, disposition, error):
    review = reviewed(workflow, disposition=disposition)
    with pytest.raises(error):
        workflow[3].request_promotion(review)


def test_default_deny_and_incident_review_not_response_review(workflow):
    planning, plan, policy, _, _, _, _ = workflow
    service = PromotionService(store=planning[3], registry=planning[5], policy=policy)
    intent = service.request_review(
        plan,
        plan.proposed_actions[0].proposal_id,
        reviewer_id="reviewer-alice",
        disposition="reject",
        reason="Not authenticated",
    )
    with pytest.raises(HumanAuthorizationDenied):
        service.record_review(intent, credential="reviewer-alice")
    with pytest.raises(InvalidPromotionArtifact):
        service.request_promotion(planning[2])


def test_blockers_require_explicit_human_responses(workflow):
    with pytest.raises(ValueError, match="blocker"):
        workflow[3].request_review(
            workflow[1],
            workflow[1].proposed_actions[0].proposal_id,
            reviewer_id="reviewer-alice",
            disposition="ready_for_promotion",
            reason="Missing responses",
        )


@pytest.mark.parametrize(
    "part",
    [
        "review_id",
        "review_reason",
        "request_id",
        "proposal_digest",
        "plan_id",
        "incident_id",
        "target",
        "policy",
    ],
)
def test_forged_artifact_rejected(workflow, part):
    review = reviewed(workflow)
    request = workflow[3].request_promotion(review)
    if part == "review_id":
        with pytest.raises(InvalidPromotionArtifact):
            workflow[3].request_promotion(review.model_copy(update={"review_id": uuid4()}))
        return
    if part == "review_reason":
        intent = review.intent.model_copy(update={"reason": "Substituted human decision"})
        with pytest.raises(InvalidPromotionArtifact):
            workflow[3].request_promotion(review.model_copy(update={"intent": intent}))
        return
    payload = request.model_dump()
    if part == "request_id":
        payload["request_id"] = uuid4()
    elif part in ("proposal_digest", "plan_id", "incident_id"):
        field = "response_plan_id" if part == "plan_id" else part
        payload["target"][field] = uuid4() if part == "incident_id" else "0" * 64
    elif part == "target":
        payload["target"]["proposal"]["details"]["intent"]["proposed_input"] = '{"target":"other"}'
    else:
        payload["target"]["proposal"]["details"]["policy_preflight"]["decision"] = "deny"
    forged = type(request).model_construct(**payload)
    with pytest.raises(InvalidPromotionArtifact):
        workflow[3].promote(forged)


@pytest.mark.parametrize("change", ["evidence", "severity", "status", "closed"])
def test_current_state_change_rejected(workflow, change):
    planning, _, _, service, *_ = workflow
    request = service.request_promotion(reviewed(workflow))
    state, _, review, store, incident_service, *_ = planning
    if change == "evidence":
        store.append_evidence(
            review.target.snapshot,
            Evidence(
                incident_id=state.incident_id,
                source="later",
                summary="Later",
                raw_data="{}",
                observed_at=utc_now(),
            ),
        )
    else:
        # Storage fixture simulates a separate authoritative writer. The retained
        # state is validated and revisioned, not a mutation of the caller's object.
        from soc_agent.review.persistence.session import GovernanceSession

        with store.database.transaction() as connection:
            session = GovernanceSession(connection, store.store_id)
            updated = state.model_dump() | (
                {"severity": "high"}
                if change == "severity"
                else {"status": "closed" if change == "closed" else "triaging"}
            )
            session.save_state(review.target.snapshot, type(state).model_validate(updated))
    with pytest.raises(IncidentClosed if change == "closed" else StaleSnapshotError):
        service.promote(request)


@pytest.mark.parametrize("change", ["removed", "permission", "risk", "description", "schema"])
def test_tool_change_rejected(workflow, change):
    planning, _, _, service, *_ = workflow
    request = service.request_promotion(reviewed(workflow))
    registry = planning[5]
    old = registry.get("inspect_logs")
    if change == "removed":
        del registry._tools["inspect_logs"]
        error = PromotionToolMissing
    elif change == "schema":
        from pydantic import BaseModel

        class NewInput(BaseModel):
            target: str
            count: int = 1

        registry._tools["inspect_logs"] = Tool(
            metadata=old.metadata,
            input_model=NewInput,
            output_model=old.output_model,
            handler=old.handler,
        )
        error = InputSchemaChanged
    else:
        metadata = old.metadata.model_dump() | {
            "risk_level" if change == "risk" else change: {
                "permission": "network_write",
                "risk": "high",
                "description": "Changed",
            }[change]
        }
        registry._tools["inspect_logs"] = Tool(
            metadata=type(old.metadata).model_validate(metadata),
            input_model=old.input_model,
            output_model=old.output_model,
            handler=old.handler,
        )
        error = ToolMetadataChanged
    with pytest.raises(error):
        service.promote(request)


@pytest.mark.parametrize("tool", ["inspect_logs", "test_response", "test_destructive"])
def test_current_deny_cannot_be_overridden(workflow, tool):
    request = workflow[3].request_promotion(reviewed(workflow, tool))
    workflow[2].override = PolicyDecision.DENY
    with pytest.raises(PromotionPolicyDenied):
        workflow[3].promote(request)


def test_write_cannot_be_weakened(workflow):
    request = workflow[3].request_promotion(reviewed(workflow, "test_response"))
    workflow[2].override = PolicyDecision.ALLOW
    with pytest.raises(PromotionPolicyChanged):
        workflow[3].promote(request)


def test_current_stronger_policy_is_preserved(workflow):
    request = workflow[3].request_promotion(reviewed(workflow))
    workflow[2].override = PolicyDecision.REQUIRE_APPROVAL
    value = workflow[3].promote(request)
    assert value.content.current_policy.decision == PolicyDecision.REQUIRE_APPROVAL
    assert (
        value.content.request.target.proposal.details.policy_preflight.decision
        == PolicyDecision.ALLOW
    )
