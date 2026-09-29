"""Test-only provider composition using the existing identity and governance fixtures."""

import pytest
from tests.unit.durable_execution.conftest import durable as durable
from tests.unit.identity.conftest import Boundary
from tests.unit.persistence.conftest import prepared as prepared
from tests.unit.promotion.conftest import case as case
from tests.unit.promotion.conftest import planning as planning
from tests.unit.promotion.conftest import workflow as workflow

from soc_agent.execution.durable import migrate
from soc_agent.review.authentication import ProviderHumanAuthority
from soc_agent.review.authorization import RBACPermissionVerifier
from soc_agent.review.persistence.confirmations import (
    SQLiteConfirmationConsumer,
    migrate_confirmations,
)


def authority_for(boundary, consumer):
    return ProviderHumanAuthority(
        provider=boundary.provider,
        provider_id="test-identity",
        permissions=RBACPermissionVerifier(roles=boundary.roles),
        resolve_context=lambda action, digest: boundary.contexts[(action, digest)],
        clock=lambda: boundary.now,
        confirmation_consumer=consumer,
    )


@pytest.fixture
def boundary(planning):
    database = planning[3].database
    migrate(database)
    migrate_confirmations(database)
    value = Boundary()
    value.authority = authority_for(value, SQLiteConfirmationConsumer(database))
    return value
