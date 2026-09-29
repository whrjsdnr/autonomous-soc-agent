# Phase 4-8 — Trusted Identity & Authorization Boundary

Authentication does not override Policy.
Authorization does not imply Tool Approval.
Human confirmation is request-specific.
Test authentication providers are not production identity providers.

## Identity

This phase extends the existing `review.authentication` interfaces rather than
introducing another identity system. Frozen `AuthenticatedPrincipal` retains
subject/provider, human subject kind, authentication context (provider-described
methods), authentication time, expiry and scopes; it now requires a nonempty
session reference. These models are data, not credentials or proof of identity.

`ProviderHumanAuthority.verify` accepts opaque credentials only. It obtains and
revalidates the principal through the explicitly injected AuthenticationProvider,
checks the configured provider, session lifetime and maximum authentication age.
A caller-created principal, username, email or role string cannot replace this
step. Constructing a principal in Python grants no authority. Trusted startup
composition selects providers; this is not a sandbox against malicious Python
implementations supplied by that composition root.

No production provider is supplied or selected. Existing governance services
continue to default to DenyHumanAuthority. Tests put their fake provider and role
lookup exclusively in `tests/unit/identity/conftest.py`.

## RBAC and resource authorization

`RBACPermissionVerifier` implements the existing HumanPermissionVerifier protocol.
It obtains roles from an injected HumanRoleProvider, which must resolve assignments
from trusted records using **provider + subject + incident context**. Request-body
roles and principal scope strings do not grant roles. Missing assignments, unknown
roles and lookup failures deny authorization. Providers and permission verifiers
have no permissive fallback.

| Role | Granted permission |
| --- | --- |
| ANALYST | INCIDENT_REVIEW |
| RESPONDER | RESPONSE_REVIEW |
| APPROVER | TOOL_APPROVE, EXECUTION_RECONCILE, STATE_CHANGE_AUTHORIZE |
| ADMIN | All listed human-operation permissions |

Multiple trusted roles combine permissions. STATE_CHANGE_AUTHORIZE preserves the
existing separate state-change purpose; it is never converted into TOOL_APPROVE.
ADMIN grants permission to submit a human operation, not exemption from Policy,
exact approval binding, current-state validation, replay checks or domain rules.
RBAC does not modify or replace PolicyEngine.

## Request-specific confirmation

The existing HumanAction enum remains the purpose vocabulary: RECORD_REVIEW,
REVIEW_RESPONSE_ACTION, APPROVE_PROMOTED_TOOL, RECONCILE_EXECUTION and
AUTHORIZE_STATE_CHANGE. Each maps explicitly to one RBAC permission.

`HumanConfirmation` binds its reference, subject, provider, session, purpose,
request digest, issuance time (`confirmed_at`) and explicit expiry. Confirmation
must belong to the authenticated session, follow authentication, not be future
dated, stay within maximum age and expire no later than the principal. The clock
is read again after provider/permission calls so slow verification cannot accept a
now-expired session or confirmation.

The trusted context resolver must resolve a validated, server-side request for
that purpose/digest. Its digest includes the actual incident and target in the
existing domain intent. It must not relabel an unchanged digest as another
incident or accept caller-supplied is_admin claims. The adapter checks the resolved
purpose/digest; existing domain services independently check exact artifact and
incident bindings.

The provider contract requires fresh, explicit human confirmation and atomic
consumption/replay prevention across its deployment. The adapter additionally
rejects repeated provider/confirmation references within the retained authority
instance, serializing verification with a lock. That local set is **not durable
or distributed**. Restart-safe confirmation replay protection still belongs to the
real provider; no production implementation is claimed.

## Governance integration

The same ProviderHumanAuthority is explicitly injected at existing boundaries:

- PersistentHumanReviewService: Incident Review intent, authenticated reviewer match.
- PromotionService: Response Review intent; readiness is not Tool Approval.
- ExecutionBridge: independent exact ToolApprovalIntent before ApprovalManager.approve.
- ExecutionStore.reconcile: exact ReconciliationRequest and expected lifecycle revision.

The existing State Change Authorization boundary remains compatible. Approval,
promotion, durable execution models and DB schema are unchanged. There is no new
approval issuance API or automatic human operation. The legacy low-level
ApprovalManager still trusts its caller; operational integrations must use the
human-facing governance boundary rather than expose that manager directly.

Integration tests run an authenticated Incident Review, Response Review, separate
Tool Approval and existing durable WRITE execution; reconciliation is tested with
both sufficient and insufficient permissions. No new saved-model pipeline is
introduced.

## Audit provenance

`ProviderHumanAuthority.verification_records()` returns immutable verification
receipts containing subject/provider/session references, granted permission,
resolved purpose/context/digest, confirmation reference and timestamps. Join them
to existing review/approval/reconciliation provenance through the exact intent
digest and incident/reference context. Credentials, passwords and bearer tokens
are never included; session/confirmation references must be non-secret provider
identifiers, not raw credentials.

These receipts describe successful boundary verification, **not proof the domain
operation committed**. A subsequent domain/DB failure may occur after confirmation
was consumed. Receipts are currently in-memory and are not written into existing
SQLite records; there is no migration or claim of durable identity audit. Existing
domain audit continues to record its subject attribution. Durable receipt storage
and atomic correlation with domain outcomes remain future work.

## Security boundaries and limitations

Unauthenticated/forged principal inputs, unknown/insufficient roles, expired or
cross-session confirmations, wrong purposes/digests and cross-incident request
reuse fail closed. Authentication, role lookup or confirmation failures propagate
as failures; no governance operation is authorized on dependency failure.
Provider errors may propagate to the caller; applications must sanitize their
operational logs rather than log raw provider exceptions or credentials.

There is no Auth0/Okta/Entra integration, OAuth/OIDC server, JWT implementation,
password database, login UI, production secret or distributed identity service.
Authentication strength, session revocation, role assignment integrity and
cross-process confirmation consumption require a real trusted provider/role
service. Human reconciliation references remain human assertions, not automated
proof of external effects. Phase 4-7's external-effect and SQLite limitations are
unchanged; no exactly-once execution or tamper-proof audit is claimed.

The adapter contract now requires session_id in principals and confirmations,
and expires_at in confirmations. Existing test adapters using this interface were
updated without weakening their denial assertions. Direct HumanAuthority test
fixtures remain explicitly test-only and do not become production authentication.

## Verification

- New identity/integration tests: **30 passed**, exit 0.
- Related governance regression: **325 passed**, exit 0.
- Full suite, run once: **1,771 passed in 370.77s**, exit **0** (baseline 1,741).
- Full log: `/tmp/soc-phase48-full.log`; recorded exit: `/tmp/soc-phase48-full.exit`.
- Ruff, format and diff checks passed. No existing denial assertions were weakened.
