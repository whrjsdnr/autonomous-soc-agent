from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from soc_agent.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus


def test_defaults_and_immutable_snapshot(pending: ApprovalRequest) -> None:
    assert pending.status is ApprovalStatus.PENDING
    assert pending.decision is None
    assert pending.approval_id.version == 4
    assert pending.created_at.utcoffset() == timedelta(0)
    assert ApprovalRequest.model_validate_json(pending.model_dump_json()) == pending
    with pytest.raises(ValidationError):
        pending.status = ApprovalStatus.APPROVED


@pytest.mark.parametrize(
    "update",
    [
        {"reason": "  "},
        {"tool_name": "bad name"},
        {"incident_id": "bad uuid"},
        {"permission": "unknown"},
        {"risk_level": "unknown"},
        {"status": "unknown"},
        {"status": "approved"},
        {"created_at": datetime(2026, 1, 1)},
        {"extra": True},
    ],
)
def test_invalid_request(pending: ApprovalRequest, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ApprovalRequest.model_validate(pending.model_dump() | update)


@pytest.mark.parametrize(
    "update",
    [
        {"status": "pending"},
        {"status": True},
        {"decided_by": " "},
        {"decided_at": datetime(2026, 1, 1)},
        {"extra": True},
    ],
)
def test_invalid_human_decision(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ApprovalDecision.model_validate({"status": "approved", "decided_by": "operator"} | update)


def test_decision_consistency(pending: ApprovalRequest) -> None:
    decision = ApprovalDecision(status=ApprovalStatus.APPROVED, decided_by="operator")
    for update in (
        {"decision": decision},
        {"status": "rejected", "decision": decision},
        {
            "status": "approved",
            "decision": {
                "status": "approved",
                "decided_by": "operator",
                "decided_at": pending.created_at - timedelta(seconds=1),
            },
        },
    ):
        with pytest.raises(ValidationError):
            ApprovalRequest.model_validate(pending.model_dump() | update)


def test_timestamp_normalization(pending: ApprovalRequest) -> None:
    local = datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))
    request = ApprovalRequest.model_validate(pending.model_dump() | {"created_at": local})
    decision = ApprovalDecision(
        status=ApprovalStatus.REJECTED, decided_by="operator", decided_at=local
    )
    assert request.created_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert request.created_at.utcoffset() == decision.decided_at.utcoffset() == timedelta(0)
