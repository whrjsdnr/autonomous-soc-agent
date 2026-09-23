# Phase 4-4 — Persistent Governance Infrastructure

## Purpose and boundaries

Phase 4-4 persists the Phase 4-3 human review and explicit state application flow.
Decision creation, review, change proposal, authorization and application remain
separate operations. No inference, automatic review, automatic approval, response
planning, Tool execution or Policy modification is added. Existing Tool Approval
is not a State Change Authorization. Existing in-memory APIs and tests remain.

The production authentication provider is **not implemented or connected**. The
persistent service defaults to the existing denying HumanAuthority. Tests inject
an explicitly test-only confirmation adapter; this is not operational identity
verification. Synthetic scenarios use real saved ML packages and a Mock LLM,
with a separate simulated external human authentication boundary.

## Storage choice and configuration

Python's standard-library SQLite supports reproducible local development without
a server, new dependency or ORM. Use an explicit absolute path in a private
existing directory (0700). Creation uses exclusive file creation with mode 0600;
opening requires an existing regular private file and rejects a symlink at the
file path. There is no global connection, hidden path, memory fallback or
initialization-on-open. Database files and sidecars are gitignored.

```python
from pathlib import Path
from soc_agent.review.persistence import (
    SQLiteGovernanceStore,
    PersistentHumanReviewService,
)

# Provision this directory separately, outside the source checkout, mode 0700.
path = Path("/private/local-governance/incidents.sqlite")
store = SQLiteGovernanceStore.create(path)  # Once; refuses an existing file.
service = PersistentHumanReviewService(store=store)  # Human operations deny by default.
# On restart: store = SQLiteGovernanceStore(path)
```

The service exposes the existing request_review, record_review, propose_change,
authorize_change and apply signatures. Trusted startup composition may inject a
HumanAuthority. Passing a plain subject name never grants rights.

## Schema version 1

`PRAGMA user_version=1` is checked on open and each transaction. Unsupported
versions fail without reset. There are no migrations yet. Schema creation is
transactional; a failed initialization file is left for explicit operator
inspection rather than silently reused.

| Table | Stored contract |
| --- | --- |
| metadata | Stable repository UUID |
| incidents | Unique incident ID, current revision, full fingerprint, state JSON |
| snapshots | Full validated historical state by incident/revision |
| decisions | Full decision, keyed by canonical content digest |
| review_requests, reviews | Explicit review targets and human records |
| requests | Exact status/severity proposal and target snapshot |
| authorizations | Exact issued authorization, consumed flag, application reference |
| applications | Immutable successful result and Phase 4-3 application audit |
| audit_events | Sequenced event records, UUIDs and content digests |

Artifact foreign keys bind parent and incident together. Unique constraints
prevent duplicate IDs, multiple authorizations for one request, multiple reviews
for one review request and multiple results for one authorization. Authorization
consumption references its result through a deferred foreign key. Domain checks
remain mandatory; SQL constraints do not replace them.

States and artifacts use Pydantic JSON serialization, UUID/enum/time validation
and canonical JSON digests. Reads reject invalid JSON, invalid enums, missing
fields silently filled by defaults, digest mismatches and broken references.
No empty/default incident recovery is attempted. Historical snapshots allow
validation of original review bindings after later successful changes. This does
not retroactively prove Assessment and IncidentState were produced simultaneously.

The persistence session restores the existing service's private issuance ledgers
only from validated database rows. This is an internal compatibility bridge,
not a public API for submitting caller-created authorization ledgers. Changes to
Phase 4-3 ledger internals must update this bridge and its regression tests.

## Atomic CAS and authorization consumption

Every write uses a fresh connection, foreign keys enabled, synchronous FULL and
`BEGIN IMMEDIATE`. Newly created databases use SQLite's default DELETE rollback
journal. Read operations use a transaction for a consistent view. The lock
wait is bounded (default five seconds); database contention/errors do not retry
an approval on a new snapshot.

Inside one write transaction, application restores and validates the reference
graph and checks the caller's state, exact registered decision/review/request/
authorization, repository UUID, incident, revision, full-state fingerprint and
before values. It reuses Phase 4-3 change and transition validation. The UPDATE
also has incident/revision/fingerprint predicates and must affect exactly one row.
The generated result is checked against precisely the authorized fields.

The following either all commit or all roll back:

1. Current state and revision update, plus retained historical snapshot.
2. Exact authorization consumption and result reference.
3. Application Result insertion.
4. Success audit event insertion.

INSERT/UPDATE success counts are checked for artifacts, audit and authorization
consumption so a silently ignored write cannot be reported as successful.
An unregistered or modified authorization fails. Successful consumption persists
across process restarts. Failure before commit does not consume the authorization.
There is no automatic reconciliation-and-reapply operation.

Evidence ingestion is a separate explicit append_evidence CAS API using the
existing Evidence contract. It advances revision and fingerprints the entire
state; it invalidates pending authorizations even when status/severity are unchanged.
It is not a generic arbitrary-state replacement API.

## Transition and governance rules

Phase 4-3 transition version is preserved: NEW → TRIAGING → INVESTIGATING →
ASSESSING → CLOSED, with ASSESSING → INVESTIGATING also permitted. CLOSED is
terminal here. Severity changes require explicit human selection and authorization
on nonclosed incidents. Only status and severity are change-request fields.
Evidence, Policy, Tool approvals and Registry cannot be changed through a request.
Decision advisory severity is never copied automatically. Fusion confidence stays
UNKNOWN and grants no authority. No inference or decision regeneration happens
in this layer.

## Authentication, permission and exact human intent

`authentication.py` defines AuthenticationProvider, AuthenticatedPrincipal,
HumanPermissionVerifier, HumanActionContext and HumanConfirmation.
ProviderHumanAuthority is an opt-in adapter to the existing HumanAuthority:

1. Resolve the exact binding digest to validated server-side incident/change context.
2. Authenticate opaque credentials using an explicitly injected trusted provider.
3. Check provider identity, human subject, authentication age and expiration.
4. Independently enforce incident/change-specific permissions.
5. Verify a fresh explicit confirmation for this subject, action and exact digest.

Principal/confirmation model shape is not proof of identity. Only a trusted
provider's verified result is accepted by this adapter; callers cannot pass a
principal object in place of credentials. The provider must implement real token
verification and confirmation replay prevention. Scope strings alone are not an
authorization policy. No permissive provider or role/is_admin shortcut ships.
The context resolver and permission verifier are trusted composition dependencies.

Provider verification currently runs inside the write transaction. Providers must
use bounded verification latency; interactive human interaction must happen
before calling the service, not while holding its database lock. No UI or external
identity service has been provisioned. The test adapters live under tests only.
A provider confirmation consumed externally before a DB failure is not rolled
back by SQLite; the caller may need fresh human confirmation. Never assume a
cross-system transaction with an external identity provider.

## Audit, failures and commit uncertainty

Events distinguish incident registration, evidence append, review request/record,
change request, authorization issuance/rejection, review rejection, application
success/failure and uncertain outcomes. Where available they retain incident,
decision, review, request, authorization, actor, before/after anchors, exact
changes, rule version and time. Failure records contain exception categories,
not credentials or raw exception contents. Application Result carries its own
linked application audit.

Failure audits run in a **separate** transaction after rollback. Their persistence
can itself fail, reported as FailureAuditUnavailable with the original cause.
They never represent a partly updated state as a success. Success audit failure
rolls back the entire application. Append-oriented APIs and digests are not a
cryptographic, externally witnessed or tamper-proof audit log; DB administrators
can rewrite data and matching digests.

A commit error while the connection still has an active transaction is rolled
back. If commit may already have completed, CommitOutcomeUnknown is raised;
no claim is made that a completed commit was undone. Use a fresh store and
`authorization_status(authorization_id)` to retrieve consumed state and its
validated Application Result, or inspect persisted request/authorization records
for uncertain issuance. Do not blindly retry. If the DB remains unavailable,
the outcome remains unknown. Network response failure after a successful return
cannot undo the committed transaction.

## Recovery and supported concurrency

Reopening the same file preserves repository UUID, state, revision, full snapshots,
reviews, requests, authorizations, consumption, results and events. Independent
spawned Python processes compete on the same local SQLite file. Tests verify
exactly one success for the same authorization and for different authorizations
against the same revision: revision increases once, one authorization is consumed,
and one success event/result exists. Another spawned process applies and a further
process rejects replay. Forced process exit during an uncommitted write verifies
SQLite journal rollback on reopen.

This supports local same-host processes using a filesystem with SQLite locking
semantics. It does not promise distributed availability, multiple host/NFS usage,
replication, failover or high write throughput. Each operation currently reloads
the governance graph; this deliberately favors correctness over large-scale
performance. No automatic retention or deletion of sensitive historical data is
implemented.

## Operations and remaining deployment work

Directory/file checks reduce accidental disclosure, but do not authenticate the
filesystem owner or eliminate path replacement races against a privileged local
attacker. Parent directory integrity, service OS identity and permissions are
operator responsibilities. There is no encryption at rest or key management.
Use SQLite's supported backup mechanism or an offline consistent backup of the
whole database, not a live partial file copy. Test restoration in isolation.
Restoring an old backup can rewind consumed approvals; deployment must prevent
old active authorities from resuming and reconcile the restored lineage. No
cross-backup rollback protection is implemented.

Before deployment: connect and security-review a real authentication provider,
permission verifier and request confirmation mechanism; provision private local
storage; define backup, retention and recovery procedures; exercise filesystem
and hardware durability expectations; address scale and identity lifecycle.
None of these operational integrations or a production deployment is claimed.

## Verification

Test results are recorded after final validation below. New tests cover durable
contracts, malformed storage, default denial, forged and stale bindings, SQL
failure injection, serialization/lookup failures, ignored writes, commit ambiguity,
restart, real process contention and real saved-model synthetic scenarios.
Existing Phase 4-3 tests and governance behavior are retained unchanged.

Final validation (2026-09-23, offline uv):

- New unit tests: **48 passed**, exit 0 (`/tmp/soc-phase44-unit.log`).
- Integration/process suite: **13 passed**, exit 0
  (`/tmp/soc-phase44-integration.log`): 4 independent-process tests and 9 real
  saved-package synthetic scenarios.
- Full `pytest -v`: **1,540 passed in 279.70s**, exit **0**, versus the previous
  1,479 baseline (+61). Log: `/tmp/soc-phase44-full.log`.
- `ruff check .`, `ruff format --check .`, and `git diff --check`: passed.

No existing tests were removed or weakened. No commit or push was performed.
The pre-existing untracked `tests/fusion_support.py` was preserved unchanged.
