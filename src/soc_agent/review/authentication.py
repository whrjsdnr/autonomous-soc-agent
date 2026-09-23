"""Provider-backed authentication, resource authorization and human confirmation are distinct.

No provider, token parser, credentials or permissive implementation is selected by default.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from pydantic import Field

from soc_agent.review.authority import HumanAction, VerifiedHumanAction
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.models import Frozen, Hash, StateChange, Subject
from soc_agent.review.validation import checked
from soc_agent.state.evidence import UTCTimestamp, utc_now


class AuthenticatedPrincipal(Frozen):
    subject_id: Subject
    provider_id: Subject
    subject_kind: Literal["human"]
    authentication_context: tuple[Subject, ...] = Field(min_length=1)
    authenticated_at: UTCTimestamp
    expires_at: UTCTimestamp
    scopes: tuple[Subject, ...]


class HumanActionContext(Frozen):
    incident_id: UUID
    action: HumanAction
    binding_digest: Hash
    decision_id: Hash
    review_id: UUID | None = None
    request_id: UUID | None = None
    changes: tuple[StateChange, ...] = ()


class HumanConfirmation(Frozen):
    confirmation_id: Subject
    subject_id: Subject
    provider_id: Subject
    action: HumanAction
    binding_digest: Hash
    confirmed_at: UTCTimestamp


class AuthenticationProvider(Protocol):
    def authenticate(self, credential: str) -> AuthenticatedPrincipal:
        """Verify credentials with the real provider; never trust request-body principal claims."""
        ...

    def confirm(
        self, credential: str, principal: AuthenticatedPrincipal, context: HumanActionContext
    ) -> HumanConfirmation:
        """Verify explicit human intent for exact context, freshness and replay protection."""
        ...


class HumanPermissionVerifier(Protocol):
    def require_permission(
        self, principal: AuthenticatedPrincipal, context: HumanActionContext
    ) -> None:
        """Enforce rights for this incident and these exact changes, or raise denial."""
        ...


class ProviderHumanAuthority:
    """Opt-in adapter implementing the Phase 4-3 HumanAuthority protocol.

    All dependencies must come from trusted composition. Context resolution must
    use validated server-side requests, never caller-chosen is_admin/role claims.
    The provider and permission verifier have no default/allow-all implementations.
    """

    def __init__(
        self,
        *,
        provider: AuthenticationProvider,
        provider_id: str,
        permissions: HumanPermissionVerifier,
        resolve_context: Callable[[HumanAction, str], HumanActionContext],
        clock: Callable[[], datetime] = utc_now,
        maximum_age: timedelta = timedelta(minutes=5),
    ) -> None:
        if not provider_id.strip() or maximum_age <= timedelta(0):
            raise ValueError("Explicit provider identity and positive maximum age required")
        self._provider = provider
        self._provider_id = provider_id
        self._permissions = permissions
        self._resolve = resolve_context
        self._clock = clock
        self._maximum_age = maximum_age

    def verify(
        self, *, credential: str, action: HumanAction, binding_digest: str
    ) -> VerifiedHumanAction:
        if not isinstance(credential, str) or not credential:
            raise HumanAuthorizationDenied("Provider credentials required, not principal claims")
        context = checked(HumanActionContext, self._resolve(action, binding_digest))
        if (context.action, context.binding_digest) != (action, binding_digest):
            raise HumanAuthorizationDenied("Resolved human action context mismatch")
        principal = checked(AuthenticatedPrincipal, self._provider.authenticate(credential))
        now = self._clock()
        if (
            principal.provider_id != self._provider_id
            or not principal.authenticated_at <= now < principal.expires_at
            or now - principal.authenticated_at > self._maximum_age
        ):
            raise HumanAuthorizationDenied("Untrusted or stale authenticated principal")
        self._permissions.require_permission(principal, context)
        confirmation = checked(
            HumanConfirmation, self._provider.confirm(credential, principal, context)
        )
        if (
            confirmation.provider_id != principal.provider_id
            or confirmation.subject_id != principal.subject_id
            or confirmation.action != action
            or confirmation.binding_digest != binding_digest
            or not principal.authenticated_at <= confirmation.confirmed_at <= now
            or now - confirmation.confirmed_at > self._maximum_age
        ):
            raise HumanAuthorizationDenied(
                "Human confirmation does not bind the authenticated action"
            )
        return VerifiedHumanAction(
            subject_id=principal.subject_id, action=action, binding_digest=binding_digest
        )
