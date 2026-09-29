"""Reuse existing operation assertions, additionally verify durable consumption records."""

import pytest
from tests.unit.identity.test_governance import flow as flow
from tests.unit.identity.test_governance import (
    test_identity_through_review_approval_and_durable_execution as run_execution,
)
from tests.unit.identity.test_governance import (
    test_reconciliation_specific_permission as run_reconciliation,
)

from soc_agent.review.authorization import HumanRole
from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer


def assert_consumed(flow):
    consumer = SQLiteConfirmationConsumer(flow[2].database)
    records = flow[-1].authority.verification_records()
    for record in records:
        stored = consumer.load(record.provider_id, record.confirmation_id)
        assert stored.consumed
        assert stored.verification == record


@pytest.mark.asyncio
async def test_durable_review_response_tool_execution(flow):
    await run_execution(flow)
    assert len(flow[-1].authority.verification_records()) == 3
    assert_consumed(flow)


@pytest.mark.parametrize(
    "roles,allowed", [((HumanRole.ANALYST,), False), ((HumanRole.APPROVER,), True)]
)
def test_durable_reconciliation_permission(flow, roles, allowed):
    run_reconciliation(flow, roles, allowed)
    assert len(flow[-1].authority.verification_records()) == (4 if allowed else 3)
    assert_consumed(flow)
