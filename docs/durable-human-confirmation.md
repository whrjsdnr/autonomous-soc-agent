# Phase 4-9 — Durable Human Confirmation

## Scope and construction

Phase 4-8's AuthenticationProvider, RBAC, exact request confirmation and governance
interfaces remain. Inject `SQLiteConfirmationConsumer` into `ProviderHumanAuthority`
as `confirmation_consumer`. No provider, credential issuer, Policy exception or
approval system is added. The provider must still authenticate and verify explicit
human intent; database presence or a caller-created receipt is not authentication.

```python
from soc_agent.execution.durable import migrate
from soc_agent.review.persistence.confirmations import (
    SQLiteConfirmationConsumer,
    migrate_confirmations,
)

migrate(governance.database)  # explicit v1 -> v2, if needed
migrate_confirmations(governance.database)  # explicit v2 -> v3
consumer = SQLiteConfirmationConsumer(governance.database)
# Pass confirmation_consumer=consumer when constructing ProviderHumanAuthority,
# together with the existing provider, permissions and trusted context resolver.
```

There is no hidden database path or memory fallback after a configured consumer
fails. Omitting the consumer retains Phase 4-8's memory-only compatibility path;
it does not acquire the durable guarantees described here. All participating
processes must use the same authoritative SQLite database and provider namespace.

## Persistent contract and atomic consumption

Schema v3 adds `human_confirmations` without replacing governance or execution
tables. Its primary key is (provider_id, confirmation_id). The validated canonical
payload retains subject/provider/session, purpose, incident/request context and
digest, issuance time (`confirmed_at`), expiry, verification provenance, consumed
flag, consumed_at and consumer_reference. The consumer reference is the complete
context digest, identifying the exact intended operation, not claiming it committed.
No credential, bearer token or password is passed to this storage interface.
Provider/session/confirmation references must be non-secret identifiers.

Inside `BEGIN IMMEDIATE`, consumption validates the receipt and expiry using the
clock **after** acquiring the write lock, checks every stored binding (excluding
only re-verification time), checks unconsumed, and performs an UPDATE with consumed=0
and digest predicates. Initial verified registration and consumption share the
transaction. Changed identity/session/purpose/context/expiry cannot reuse a
reference. A consumed reference never becomes unconsumed through an API.
Reads validate models, digests and denormalized columns; no default reconstruction
of corrupt records occurs. SQL uniqueness and domain checks complement each other.

The low-level consumer is a trusted application dependency and returns no human
approval. Never expose it as an LLM/Tool endpoint or accept caller-supplied
HumanVerificationRecord as authenticated input. ProviderHumanAuthority is the
human-facing verification path.

## Four governance integrations

- Incident Review (and existing State Change Authorization): the persistent review
  service binds a per-operation authority/consumer to its existing transaction.
  Consumption, review/authorization record and existing audit commit or roll back
  together. This avoids a second SQLite writer inside an already-held write lock.
- Response Review and Tool Approval: the injected authority commits consumption
  before returning verified human identity to the existing operation.
- Durable Reconciliation: consumption commits before the existing reconciliation
  transaction; purpose, digest and permissions remain independently checked.

No shared mutable connection scope is installed on the long-lived authority.
Per-operation copies share only locked memory bookkeeping; durable verification
never holds that memory lock while waiting for SQL. SQLite is the authoritative
cross-process consumption guard.

Consumption is not proof of a committed downstream operation. Response Review,
Tool Approval or reconciliation can fail after consuming the confirmation. Such a
confirmation stays spent; obtain a new explicit human confirmation, never silently
reuse it. An external provider's own consumption cannot be rolled back by SQLite.
Existing Policy DENY, exact WRITE approval, promotion and execution replay rules
are unchanged. No automatic operation or retry is introduced.

## Failure, restart and migration

The existing transaction helper distinguishes known rollback from an uncertain
commit. Any DB/commit error prevents the governance call from reporting success.
A lost commit response is never treated as proof that the confirmation is unused.
Use a **fresh** consumer's `load(provider_id, confirmation_id)` to inspect state;
this read does not authorize a retry or replay a domain operation. If the DB is
unavailable the outcome remains unknown. Local receipts may exist before an outer
review transaction commits; the durable row/domain record is the recovery source.

Migration requires v2; v1 callers explicitly apply the existing execution migration
first. V3 is idempotent. Unsupported versions fail without reset. DDL/version change
is transactional; existing incidents, reviews, state authorizations, execution
records/events and governance audit are preserved. Opening does not auto-migrate.
No downgrade is provided. Earlier execution APIs accept v2/v3 without changing
execution schemas or semantics.

Independent Python processes test simultaneous consumption (one success), a fresh
interpreter's replay rejection, and data preservation. Tests reuse the Phase 4-8
four-operation fixtures; no new saved-model E2E was introduced.

## Limits

Durable replay resistance covers one authoritative local SQLite ledger on a host
with correct filesystem locking. It is not distributed identity, cross-database
coordination or protection against an administrator rewriting data. Old-backup
restoration can rewind consumption; deployment must manage rollback/recovery.
Existing private-path/file permissions and commit-uncertainty behavior are reused.
There is no production IdP, OAuth/JWT implementation, cryptographic audit ledger
or atomic transaction with an external authentication service. Providers remain
responsible for credential authenticity and explicit human intent. Plain names,
roles and model shapes confer no trust. SQLite confirmation consumption does not
provide exactly-once external execution.
