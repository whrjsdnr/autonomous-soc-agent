"""Test-only identity provider; opaque in-memory credentials are not production auth."""

from datetime import timedelta
from uuid import uuid4

import pytest
from tests.unit.promotion.conftest import case as case
from tests.unit.promotion.conftest import planning as planning
from tests.unit.promotion.conftest import workflow as workflow

from soc_agent.review.authentication import (
    AuthenticatedPrincipal,
    HumanActionContext,
    HumanConfirmation,
    ProviderHumanAuthority,
)
from soc_agent.review.authorization import RBACPermissionVerifier
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.state.evidence import utc_now


class TestProvider:
    __test__ = False

    def __init__(self):
        self.principals = {}
        self.confirmations = {}
        self.used = set()
        self.failure = None

    def authenticate(self, credential):
        if self.failure:
            raise self.failure
        if credential not in self.principals:
            raise HumanAuthorizationDenied("No authenticated test session")
        return self.principals[credential]

    def confirm(self, credential, principal, context):
        confirmation = self.confirmations[credential]
        if confirmation.confirmation_id in self.used:
            raise HumanAuthorizationDenied("Confirmation already consumed by test provider")
        self.used.add(confirmation.confirmation_id)
        return confirmation


class TestRoles:
    __test__ = False

    def __init__(self):
        self.assignments = {}
        self.failure = None

    def roles_for(self, principal, context):
        if self.failure:
            raise self.failure
        return self.assignments.get(
            (principal.provider_id, principal.subject_id, context.incident_id), ()
        )


class Boundary:
    def __init__(self):
        self.now = utc_now()
        self.provider = TestProvider()
        self.roles = TestRoles()
        self.contexts = {}
        self.authority = ProviderHumanAuthority(
            provider=self.provider,
            provider_id="test-identity",
            permissions=RBACPermissionVerifier(roles=self.roles),
            resolve_context=lambda action, digest: self.contexts[(action, digest)],
            clock=lambda: self.now,
        )

    def issue(self, context: HumanActionContext, roles, subject="reviewer-alice"):
        # Only test setup calls this; production exposes no issuance from caller strings.
        token = str(uuid4())
        principal = AuthenticatedPrincipal(
            subject_id=subject,
            provider_id="test-identity",
            session_id=str(uuid4()),
            subject_kind="human",
            authentication_context=("test-mfa",),
            authenticated_at=self.now,
            expires_at=self.now + timedelta(minutes=4),
            scopes=(),
        )
        confirmation = HumanConfirmation(
            confirmation_id=str(uuid4()),
            subject_id=subject,
            provider_id=principal.provider_id,
            session_id=principal.session_id,
            action=context.action,
            binding_digest=context.binding_digest,
            confirmed_at=self.now,
            expires_at=self.now + timedelta(minutes=1),
        )
        self.contexts[(context.action, context.binding_digest)] = context
        self.provider.principals[token] = principal
        self.provider.confirmations[token] = confirmation
        self.roles.assignments[(principal.provider_id, subject, context.incident_id)] = roles
        return token


@pytest.fixture
def boundary():
    return Boundary()
