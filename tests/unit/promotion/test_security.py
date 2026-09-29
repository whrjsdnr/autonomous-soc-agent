"""Adversarial substitutions, purpose separation and execution-time checks."""

from uuid import uuid4

import pytest
from pydantic import field_validator
from tests.unit.advisory.conftest import create
from tests.unit.promotion.conftest import approve, promoted, reviewed

from soc_agent.execution import ActionProposal as ExecutableAction
from soc_agent.execution.errors import ApprovalBindingError
from soc_agent.response.promotion.errors import (
    InvalidPromotionArtifact,
    PromotionInputInvalid,
    ToolMetadataChanged,
)
from soc_agent.review import HumanAuthorizationDenied
from soc_agent.review.authority import HumanAction
from soc_agent.review.identity import content_digest
from soc_agent.tools import Tool


@pytest.mark.parametrize(
    "purpose",
    [
        HumanAction.RECORD_REVIEW,
        HumanAction.AUTHORIZE_STATE_CHANGE,
        HumanAction.APPROVE_PROMOTED_TOOL,
    ],
)
def test_confirmation_for_wrong_purpose_rejected(workflow, purpose):
    review = reviewed(workflow)
    intent = workflow[3].request_review(
        workflow[1],
        review.intent.target.proposal.proposal_id,
        reviewer_id="reviewer-alice",
        disposition="reject",
        reason="Purpose separation",
    )
    token = workflow[6].confirm(
        subject="approver-bob", action=purpose, digest=content_digest(intent)
    )
    with pytest.raises(HumanAuthorizationDenied):
        workflow[3].record_review(intent, credential=token)


def test_unknown_review_intent_and_replayed_review_rejected(workflow):
    review = reviewed(workflow)
    service = workflow[3]
    for intent in (review.intent.model_copy(update={"intent_id": uuid4()}), review.intent):
        token = workflow[6].confirm(
            subject="reviewer-alice",
            action=HumanAction.REVIEW_RESPONSE_ACTION,
            digest=content_digest(intent),
        )
        with pytest.raises(InvalidPromotionArtifact):
            service.record_review(intent, credential=token)


@pytest.mark.parametrize("mode", ["correction", "invalid"])
def test_schema_equal_but_input_normalization_or_validation_changed(workflow, mode):
    request = workflow[3].request_promotion(reviewed(workflow))
    old = workflow[0][5].get("inspect_logs")

    # Keep the schema identical while changing runtime validation behavior.
    class Changed(old.input_model):
        @field_validator("target")
        @classmethod
        def change_target(cls, value):
            if mode == "invalid":
                raise ValueError("Input no longer valid")
            return value + "_changed"

        @classmethod
        def model_json_schema(cls, **kwargs):
            return old.input_model.model_json_schema(**kwargs)

    workflow[0][5]._tools["inspect_logs"] = Tool(
        metadata=old.metadata,
        input_model=Changed,
        output_model=old.output_model,
        handler=old.handler,
    )
    with pytest.raises(PromotionInputInvalid):
        workflow[3].promote(request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        '{"target":"host_b"}',
        '{"ip":"203.0.113.7"}',
        '{"account":"other"}',
        '{"target":"host_a","extra":true}',
    ],
)
async def test_exact_approved_input_cannot_be_substituted(workflow, payload):
    value = promoted(workflow, "test_response")
    approval = approve(workflow, value)
    workflow[4]._requests[approval.approval_id] = approval.model_copy(
        update={"action_input_json": payload}
    )
    with pytest.raises(ApprovalBindingError):
        await workflow[5].execute(value, approval_id=approval.approval_id)


@pytest.mark.asyncio
async def test_approval_from_different_proposal_cannot_be_reused(workflow):
    first = promoted(workflow, "test_response")
    approval = approve(workflow, first)
    planning = workflow[0]
    candidate = planning[7].model_copy(
        update={"candidate_tool": "test_response", "purpose": "Another intent"}
    )
    other_plan = create(planning, (candidate,))
    other_workflow = (planning, other_plan, *workflow[2:])
    second = promoted(other_workflow, "test_response")
    assert (
        first.content.request.target.proposal.proposal_id
        != second.content.request.target.proposal.proposal_id
    )
    with pytest.raises(ApprovalBindingError):
        await workflow[5].execute(second, approval_id=approval.approval_id)


@pytest.mark.asyncio
async def test_metadata_changed_after_tool_approval_rejected(workflow):
    value = promoted(workflow, "test_response")
    approval = approve(workflow, value)
    registry = workflow[0][5]
    old = registry.get("test_response")
    registry._tools["test_response"] = Tool(
        metadata=old.metadata.model_copy(update={"risk_level": "destructive"}),
        input_model=old.input_model,
        output_model=old.output_model,
        handler=old.handler,
    )
    with pytest.raises(ToolMetadataChanged):
        await workflow[5].execute(value, approval_id=approval.approval_id)


def test_promoted_is_not_executable_or_approval(workflow):
    value = promoted(workflow)
    with pytest.raises(ValueError):
        ExecutableAction.model_validate(value.model_dump())
    from soc_agent.approval import ApprovalRequest

    with pytest.raises(ValueError):
        ApprovalRequest.model_validate(value.model_dump())


def test_unresolved_blocker_cannot_be_ready(workflow):
    from soc_agent.response.promotion import BlockerResponse

    proposal = workflow[1].proposed_actions[0]
    with pytest.raises(ValueError, match="Unresolved"):
        workflow[3].request_review(
            workflow[1],
            proposal.proposal_id,
            reviewer_id="reviewer-alice",
            disposition="ready_for_promotion",
            reason="Unresolved conditions",
            blocker_responses=tuple(
                BlockerResponse(
                    blocking_reason=r, resolution="unresolved", response="More evidence needed"
                )
                for r in proposal.details.blocking_reasons
            ),
        )


@pytest.mark.asyncio
async def test_cross_incident_approval_reuse(workflow):
    from tests.review_support import record_review

    from soc_agent.assessment import ThreatAssessment
    from soc_agent.decision import IncidentDecisionEngine
    from soc_agent.response.advisory import CandidateIntent
    from soc_agent.state import Evidence, IncidentState
    from soc_agent.state.evidence import utc_now

    first = promoted(workflow, "test_response")
    approval = approve(workflow, first)
    state = IncidentState()
    state = state.add_evidence(
        Evidence(
            incident_id=state.incident_id,
            source="other incident",
            summary="Other source",
            raw_data="{}",
            observed_at=utc_now(),
        )
    )
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="high",
        confidence=0.2,
        summary="Other concern",
        supporting_evidence_ids=(state.evidence[0].evidence_id,),
    )
    decision = IncidentDecisionEngine().decide(state, assessment)
    planning = workflow[0]
    planning[3].register(state)
    review = record_review(planning[4], workflow[6], planning[4].request_review(state, decision))
    candidate = CandidateIntent(
        candidate_tool="test_response",
        proposed_input={"target": "host_a"},
        purpose="Other incident response",
        rationale="Independent consideration",
        evidence_ids=decision.evidence_ids,
    )
    other_plan = planning[6].create_plan(
        incident_state=state,
        decision=decision,
        review=review,
        objective="Other incident",
        candidates=(candidate,),
    )
    other = promoted((planning, other_plan, *workflow[2:]), "test_response")
    with pytest.raises(ApprovalBindingError):
        await workflow[5].execute(other, approval_id=approval.approval_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["severity", "status", "closed", "schema"])
async def test_final_validation_after_exact_write_approval(workflow, monkeypatch, change):
    from pydantic import BaseModel

    from soc_agent.response.promotion.errors import IncidentClosed, InputSchemaChanged
    from soc_agent.review.errors import StaleSnapshotError
    from soc_agent.review.persistence.session import GovernanceSession

    value = promoted(workflow, "test_response")
    approval = approve(workflow, value)
    planning = workflow[0]
    if change == "schema":
        old = planning[5].get("test_response")

        class NewInput(BaseModel):
            target: str
            scope: str = "limited"

        planning[5]._tools["test_response"] = Tool(
            metadata=old.metadata,
            input_model=NewInput,
            output_model=old.output_model,
            handler=old.handler,
        )
        expected = InputSchemaChanged
    else:
        state, store = planning[0], planning[3]
        updated = state.model_dump() | (
            {"severity": "high"}
            if change == "severity"
            else {"status": "closed" if change == "closed" else "triaging"}
        )
        with store.database.transaction() as connection:
            GovernanceSession(connection, store.store_id).save_state(
                value.content.current_snapshot, type(state).model_validate(updated)
            )
        expected = IncidentClosed if change == "closed" else StaleSnapshotError

    def forbidden(*args, **kwargs):
        pytest.fail("A stale approved action reached the Tool wrapper")

    monkeypatch.setattr(Tool, "execute", forbidden)
    with pytest.raises(expected):
        await workflow[5].execute(value, approval_id=approval.approval_id)
    assert workflow[5].audit_events()[-1].outcome == "rejected"
