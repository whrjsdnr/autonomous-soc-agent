from datetime import timedelta
from uuid import uuid4

import pytest

from soc_agent.review import HumanAction, HumanAuthorizationDenied
from soc_agent.review.authentication import (
    AuthenticatedPrincipal,
    HumanActionContext,
    HumanConfirmation,
    ProviderHumanAuthority,
)
from soc_agent.state.evidence import utc_now


@pytest.fixture
def boundary():
    now = utc_now()
    context = HumanActionContext(
        incident_id=uuid4(),
        decision_id="a" * 64,
        action=HumanAction.AUTHORIZE_STATE_CHANGE,
        binding_digest="b" * 64,
    )
    principal = AuthenticatedPrincipal(
        subject_id="human-1",
        provider_id="test-provider",
        subject_kind="human",
        authentication_context=("test-mfa",),
        authenticated_at=now,
        expires_at=now + timedelta(minutes=1),
        scopes=("incident:authorize",),
    )

    class Provider:
        calls = 0

        def authenticate(self, credential):
            if credential != "test-provider-proof":
                raise HumanAuthorizationDenied("Unverified credential")
            return self.principal

        def confirm(self, credential, authenticated, ctx):
            self.calls += 1
            return self.confirmation

    class Permissions:
        permitted = True

        def require_permission(self, authenticated, ctx):
            if not self.permitted or ctx.incident_id != context.incident_id:
                raise HumanAuthorizationDenied("Authenticated but not authorized")

    provider, permissions = Provider(), Permissions()
    provider.principal = principal
    provider.confirmation = HumanConfirmation(
        confirmation_id="test-confirmation",
        subject_id=principal.subject_id,
        provider_id=principal.provider_id,
        action=context.action,
        binding_digest=context.binding_digest,
        confirmed_at=now,
    )
    authority = ProviderHumanAuthority(
        provider=provider,
        provider_id="test-provider",
        permissions=permissions,
        resolve_context=lambda action, digest: context,
        clock=lambda: now,
    )
    return authority, provider, permissions, context


def test_verified_principal_then_permission_then_confirmation(boundary):
    authority, provider, permissions, context = boundary
    assert (
        authority.verify(
            credential="test-provider-proof",
            action=context.action,
            binding_digest=context.binding_digest,
        ).subject_id
        == "human-1"
    )
    permissions.permitted = False
    with pytest.raises(HumanAuthorizationDenied):
        authority.verify(
            credential="test-provider-proof",
            action=context.action,
            binding_digest=context.binding_digest,
        )
    assert provider.calls == 1


@pytest.mark.parametrize("claims", ["admin", "user@example.com", '{"is_admin":true}', "", None])
def test_unverified_strings_never_authenticate(boundary, claims):
    authority, provider, _, context = boundary
    with pytest.raises(HumanAuthorizationDenied):
        authority.verify(
            credential=claims, action=context.action, binding_digest=context.binding_digest
        )
    assert provider.calls == 0


@pytest.mark.parametrize("field", ["provider_id", "authenticated_at", "expires_at"])
def test_stale_or_wrong_provider(boundary, field):
    authority, provider, _, context = boundary
    value = (
        "untrusted"
        if field == "provider_id"
        else provider.principal.authenticated_at - timedelta(hours=1)
    )
    provider.principal = provider.principal.model_copy(update={field: value})
    with pytest.raises(HumanAuthorizationDenied):
        authority.verify(
            credential="test-provider-proof",
            action=context.action,
            binding_digest=context.binding_digest,
        )


@pytest.mark.parametrize("field", ["subject_id", "provider_id", "binding_digest", "action"])
def test_confirmation_binding(boundary, field):
    authority, provider, _, context = boundary
    value = {
        "subject_id": "other",
        "provider_id": "other",
        "binding_digest": "0" * 64,
        "action": HumanAction.RECORD_REVIEW,
    }[field]
    provider.confirmation = provider.confirmation.model_copy(update={field: value})
    with pytest.raises(HumanAuthorizationDenied):
        authority.verify(
            credential="test-provider-proof",
            action=context.action,
            binding_digest=context.binding_digest,
        )
