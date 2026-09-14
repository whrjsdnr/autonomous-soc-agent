from datetime import timedelta
from uuid import uuid4

import pytest

from soc_agent.approval import (
    ApprovalAlreadyDecidedError,
    ApprovalError,
    ApprovalManager,
    ApprovalNotFoundError,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalValidationError,
)
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.tools import ToolMetadata, ToolRiskLevel


@pytest.mark.parametrize(
    "method,status", [("approve", ApprovalStatus.APPROVED), ("reject", ApprovalStatus.REJECTED)]
)
def test_create_and_decide(metadata: ToolMetadata, method: str, status: ApprovalStatus) -> None:
    manager = ApprovalManager()
    incident_id = uuid4()
    pending = manager.create(incident_id=incident_id, metadata=metadata, reason="Review")
    assert pending.status is ApprovalStatus.PENDING
    updated = getattr(manager, method)(pending.approval_id, actor="operator-1")
    assert updated.status is status
    assert updated.decision.decided_by == "operator-1"
    assert updated.decision.decided_at >= pending.created_at
    assert updated.decision.decided_at.utcoffset() == timedelta(0)
    assert updated.incident_id == incident_id
    assert updated.tool_name == metadata.name
    assert updated.created_at == pending.created_at
    assert pending.status is ApprovalStatus.PENDING
    assert manager.get(updated.approval_id) == updated
    assert ApprovalRequest.model_validate_json(updated.model_dump_json()) == updated
    for decide in (manager.approve, manager.reject):
        with pytest.raises(ApprovalAlreadyDecidedError):
            decide(updated.approval_id, actor="another-operator")
    assert manager.get(updated.approval_id) == updated


@pytest.mark.parametrize("method", ["get", "approve", "reject"])
def test_unknown_request(method: str) -> None:
    manager = ApprovalManager()
    with pytest.raises(ApprovalNotFoundError):
        if method == "get":
            manager.get(uuid4())
        else:
            getattr(manager, method)(uuid4(), actor="operator")


def test_independent_requests_and_managers(metadata: ToolMetadata) -> None:
    first, second = ApprovalManager(), ApprovalManager()
    a = first.create(incident_id=uuid4(), metadata=metadata, reason="First")
    snapshot = first.list()
    b = first.create(incident_id=uuid4(), metadata=metadata, reason="Second")
    assert a.approval_id != b.approval_id
    first.approve(a.approval_id, actor="operator")
    assert first.get(b.approval_id).status is ApprovalStatus.PENDING
    assert snapshot == (a,)
    assert second.list() == ()


def test_invalid_inputs_do_not_change_store(metadata: ToolMetadata) -> None:
    manager = ApprovalManager()
    with pytest.raises(ApprovalValidationError):
        manager.create(incident_id=uuid4(), metadata=metadata, reason=" ")
    assert manager.list() == ()
    request = manager.create(incident_id=uuid4(), metadata=metadata, reason="Review")
    with pytest.raises(ApprovalValidationError):
        manager.approve(request.approval_id, actor=" ")
    assert manager.get(request.approval_id) == request


def test_policy_and_human_decision_boundary(metadata: ToolMetadata) -> None:
    policy = PolicyEngine()
    result = policy.evaluate(metadata)
    assert result.decision is PolicyDecision.REQUIRE_APPROVAL
    manager = ApprovalManager()
    request = manager.create(incident_id=uuid4(), metadata=metadata, reason=result.reason)
    assert request.status is ApprovalStatus.PENDING
    approved = manager.approve(request.approval_id, actor="human-reviewer")
    assert approved.status is ApprovalStatus.APPROVED
    assert policy.evaluate(metadata) == result
    destructive = ToolMetadata.model_validate(
        metadata.model_dump() | {"risk_level": ToolRiskLevel.DESTRUCTIVE}
    )
    assert policy.evaluate(destructive).decision is PolicyDecision.DENY


@pytest.mark.parametrize(
    "error", [ApprovalNotFoundError, ApprovalAlreadyDecidedError, ApprovalValidationError]
)
def test_common_error_root(error: type[ApprovalError]) -> None:
    assert isinstance(error("failure"), ApprovalError)
