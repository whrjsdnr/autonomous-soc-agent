"""Provider-backed authentication, resource authorization and human confirmation are distinct.

No provider, token parser, credentials or permissive implementation is selected by default.
"""

from collections.abc import Callable
from copy import copy
from datetime import datetime, timedelta
from sqlite3 import Connection
from threading import RLock
from typing import Literal, Protocol, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.authority import HumanAction, VerifiedHumanAction
from soc_agent.review.authorization import HumanPermission, permission_for
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.models import Frozen, Hash, StateChange, Subject
from soc_agent.review.validation import checked
from soc_agent.state.evidence import UTCTimestamp, utc_now


class AuthenticatedPrincipal(Frozen):
    subject_id: Subject
    provider_id: Subject
    session_id: Subject
    subject_kind: Literal["human"]
    authentication_context: tuple[Subject, ...] = Field(min_length=1)
    authenticated_at: UTCTimestamp
    expires_at: UTCTimestamp
    scopes: tuple[Subject, ...]


class HumanActionContext(Frozen):
    incident_id: UUID
    action: HumanAction
    binding_digest: Hash
    decision_id: Hash | None
    review_id: UUID | None = None
    request_id: UUID | None = None
    changes: tuple[StateChange, ...] = ()

    @model_validator(mode="after")
    def decision_context(self) -> Self:
        if self.decision_id is None and self.action != HumanAction.SUBMIT_ANALYST_FEEDBACK:
            raise ValueError("Governance action requires a decision reference")
        return self


class HumanConfirmation(Frozen):
    confirmation_id: Subject
    subject_id: Subject
    provider_id: Subject
    session_id: Subject
    action: HumanAction
    binding_digest: Hash
    confirmed_at: UTCTimestamp
    expires_at: UTCTimestamp


class HumanVerificationRecord(Frozen):
    """Non-secret authorization provenance, not proof the domain operation committed."""

    subject_id: Subject
    provider_id: Subject
    session_id: Subject
    permission: HumanPermission
    context: HumanActionContext
    confirmation_id: Subject
    confirmed_at: UTCTimestamp
    expires_at: UTCTimestamp
    verified_at: UTCTimestamp


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


class ConfirmationConsumer(Protocol):
    """Trusted composition dependency, not an authentication/issuance API."""

    def consume(self, record: HumanVerificationRecord) -> None: ...

    def for_transaction(
        self, repository_id: UUID, connection: Connection
    ) -> "ConfirmationConsumer": ...


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
        confirmation_consumer: ConfirmationConsumer | None = None,
    ) -> None:
        if not provider_id.strip() or maximum_age <= timedelta(0):
            raise ValueError("Explicit provider identity and positive maximum age required")
        self._provider = provider
        self._provider_id = provider_id
        self._permissions = permissions
        self._resolve = resolve_context
        self._clock = clock
        self._maximum_age = maximum_age
        self._confirmation_consumer = confirmation_consumer
        self._lock = RLock()
        self._used: set[tuple[str, str]] = set()
        self._records: list[HumanVerificationRecord] = []

    def verify(
        self, *, credential: str, action: HumanAction, binding_digest: str
    ) -> VerifiedHumanAction:
        if self._confirmation_consumer is not None:
            # SQLite serializes durable consumption. Never hold the memory lock while
            # waiting for SQL: Incident Review may already own the write transaction.
            return self._verify(credential=credential, action=action, binding_digest=binding_digest)
        with self._lock:
            return self._verify(credential=credential, action=action, binding_digest=binding_digest)

    def _verify(
        self, *, credential: str, action: HumanAction, binding_digest: str
    ) -> VerifiedHumanAction:
        if not isinstance(credential, str) or not credential:
            raise HumanAuthorizationDenied("Provider credentials required, not principal claims")
        context = checked(HumanActionContext, self._resolve(action, binding_digest))
        if (context.action, context.binding_digest) != (action, binding_digest):
            raise HumanAuthorizationDenied("Resolved human action context mismatch")
        principal = self.authenticate_context(credential=credential, context=context)
        confirmation = checked(
            HumanConfirmation, self._provider.confirm(credential, principal, context)
        )
        # Provider/authorization calls may take time. Expiration is checked again.
        now = self._clock()
        if (
            confirmation.provider_id != principal.provider_id
            or confirmation.subject_id != principal.subject_id
            or confirmation.session_id != principal.session_id
            or confirmation.action != action
            or confirmation.binding_digest != binding_digest
            or not principal.authenticated_at <= confirmation.confirmed_at <= now
            or now - confirmation.confirmed_at > self._maximum_age
            or not now < confirmation.expires_at <= principal.expires_at
            or now - principal.authenticated_at > self._maximum_age
        ):
            raise HumanAuthorizationDenied(
                "Human confirmation does not bind the authenticated action"
            )
        key = (confirmation.provider_id, confirmation.confirmation_id)
        with self._lock:
            if key in self._used:
                raise HumanAuthorizationDenied("Human confirmation already used by this authority")
        record = HumanVerificationRecord(
            subject_id=principal.subject_id,
            provider_id=principal.provider_id,
            session_id=principal.session_id,
            permission=permission_for(action),
            context=context,
            confirmation_id=confirmation.confirmation_id,
            confirmed_at=confirmation.confirmed_at,
            expires_at=confirmation.expires_at,
            verified_at=now,
        )
        if self._confirmation_consumer is not None:
            self._confirmation_consumer.consume(record)
        with self._lock:
            self._used.add(key)
            self._records.append(record)
        return VerifiedHumanAction(
            subject_id=principal.subject_id, action=action, binding_digest=binding_digest
        )

    def authenticate_context(
        self, *, credential: str, context: HumanActionContext
    ) -> AuthenticatedPrincipal:
        """Authenticate and authorize a read/retry; never substitutes for confirmation."""
        context = checked(HumanActionContext, context)
        if not isinstance(credential, str) or not credential:
            raise HumanAuthorizationDenied("Provider credentials required, not principal claims")
        principal = checked(AuthenticatedPrincipal, self._provider.authenticate(credential))
        now = self._clock()
        if (
            principal.provider_id != self._provider_id
            or not principal.authenticated_at <= now < principal.expires_at
            or now - principal.authenticated_at > self._maximum_age
        ):
            raise HumanAuthorizationDenied("Untrusted or stale authenticated principal")
        self._permissions.require_permission(principal, context)
        return principal

    def for_transaction(
        self, repository_id: UUID, connection: Connection
    ) -> "ProviderHumanAuthority":
        """Bind a per-operation copy; never mutate another thread's connection scope."""
        if self._confirmation_consumer is None:
            return self
        bound = copy(self)
        bound._confirmation_consumer = self._confirmation_consumer.for_transaction(
            repository_id, connection
        )
        return bound

    def verification_records(self) -> tuple[HumanVerificationRecord, ...]:
        """Correlate by request digest/incident with existing governance audit records.

        This memory cache contains no credential. A configured durable consumer
        also stores consumption; without it cross-process replay remains the provider's
        responsibility. Receipts do not prove the downstream operation committed.
        """
        with self._lock:
            return tuple(self._records)
