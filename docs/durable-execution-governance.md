# Phase 4-7 — Durable Execution Governance & Recovery

## Purpose and non-goals

Durable intent does not imply durable external side effects.
An EXECUTING record means invocation may have started; it does not prove success.
UNCERTAIN outcomes are never retried automatically.
SQLite state and external Tool side effects are not one atomic transaction.
Exactly-once external execution is not guaranteed.

This opt-in layer persists human-governed execution intent, reservations, lifecycle
and audit. It reuses Phase 4-6 promotion/current validation and the existing
GovernedExecutor. There is no worker, automatic execution, retry, review, promotion,
approval, reconciliation, new production Tool, authentication provider or ML model.

## Architecture and explicit API

```text
Existing registered PromotedAction + independently confirmed Tool Approval
  → ExecutionStore.create(bridge, promoted, approval_id=...)
  → durable PENDING intent with exact source lineage
  → explicit DurableExecutor.execute(intent_id, claimant=...)
  → transactional claim
  → current state / Tool / schema / exact input / Policy validation
  → transactional EXECUTING invocation boundary, COMMIT confirmed
  → existing GovernedExecutor → registered Tool (outside transaction)
  → outcome + audit transaction

Restart → explicit recover() → classify expired reservations only
UNCERTAIN → explicit request + trusted confirmation → reconcile()
```

Trusted application composition must route governed operational dispatch through
DurableExecutor and retain one authoritative ledger. Legacy ExecutionBridge and
GovernedExecutor APIs remain compatible; calling them directly bypasses this new
ledger. This is not a Python sandbox against trusted code or a DB administrator.

```python
from soc_agent.execution.durable import ExecutionStore, DurableExecutor, migrate

# governance is an explicitly created/opened SQLiteGovernanceStore.
migrate(governance.database)  # explicit additive v1 -> v2; no automatic reset
executions = ExecutionStore(governance)
record = executions.create(bridge, promoted, approval_id=approval_id)
runner = DurableExecutor(store=executions, registry=registry, policy=policy)
# Only an explicit dispatch call invokes a Tool:
result = await runner.execute(record.intent.execution_intent_id, claimant="worker-1")
```

No source plan persistence is added to the advisory planner. The execution intent
captures its full source plan, promotion/review/request and independently confirmed
approved snapshot at the explicit registration boundary. Restart does not trust a
caller-supplied promotion ledger: it reads and validates the stored capsule, then
rechecks source Incident Review provenance through Phase 4-4 storage. Tool handlers
and current Policy are installed again by trusted application composition.

## ExecutionIntent, identity and binding

Frozen Pydantic contracts retain the complete source graph. The promoted target
includes incident, plan, proposal, response review, promotion request, metadata,
exact canonical input, input schema and full repository/revision/fingerprint
anchor. Promotion Policy and the exact existing Tool Approval are retained.
Creation calls existing live service/bridge validation; merely constructing an
ExecutionIntent or an ApprovalRequest does not insert or authorize it.

ExecutionBinding contains incident, promoted identity, tool, canonical input and
approval identity (null for permitted reads). Its canonical content digest is both
execution intent identity and internal idempotency key. Creation time does not
participate. Repeated registration of identical lineage returns the existing
record without resetting lifecycle; changed lineage fails. SQL uniqueness on
promotion and non-null approval IDs prevents re-reservation with a new key or a
second approval for the same promotion.

Input model coercion is governed by Phase 4-6: the current schema must validate and
round-trip to the exact previously reviewed canonical input. No corrections occur.
Tool permission/risk/schema and planning/promotion Policy remain separate facts.

## Lifecycle and leases

Rule version: `execution-lifecycle:v1`.

| From | Explicit operation | To |
| --- | --- | --- |
| PENDING | atomic claim | CLAIMED |
| CLAIMED | successful current validation, unexpired exact claim | EXECUTING |
| CLAIMED | current validation failure | FAILED (invocation not started) |
| CLAIMED, expired | explicit recovery | PENDING |
| EXECUTING | validated Tool result persisted | SUCCEEDED |
| EXECUTING | explicit adapter-reported failure persisted | FAILED |
| EXECUTING | ambiguous exception/outcome | UNCERTAIN |
| EXECUTING, expired | explicit recovery | UNCERTAIN |
| UNCERTAIN | trusted reconciliation | SUCCEEDED / FAILED / UNCERTAIN |

SUCCEEDED and FAILED never reenter execution. UNCERTAIN cannot be claimed. Even a
confirmed failed reconciliation does not permit replay. A genuinely new operation
requires a new explicit promotion and, where required, independent human approval.

Claims include random fencing token, claimant attribution, claim/expiry timestamps
and lifecycle revision. Claimant strings are not human approvals. `BEGIN IMMEDIATE`
serializes competing claims. Every change matches the persisted complete claim and
revision/digest; recovered/replaced owners cannot enter the invocation boundary.
Lease durations are bounded to 1..3600 seconds. Clocks come from the service, not
request timestamps. Operators must maintain host clock integrity. No heartbeat or
lease extension is implemented; select duration explicitly for expected operations.

Recovery inspects only expired CLAIMED/EXECUTING records, avoiding takeover of an
unexpired owner. It does not declare a live owner's invocation absent. Expired
EXECUTING is never reclaimed, even if the original worker is still running. If a
late result races with recovery, lifecycle CAS rejects stale completion and the
caller receives an unknown-outcome error rather than dispatching again.

## Invocation boundary and current validation

Before committing EXECUTING, the runner reads the authoritative current state and
reuses CurrentValidation for repository/revision/full fingerprint, CLOSED status,
Decision/Evidence and Incident Review provenance, Tool metadata/schema, exact input
and current Policy. A changed Policy result is rejected. Stored model reads also
revalidate exact Approval incident/action/tool/input/permission/risk binding.
Validation failure is persisted as FAILED with no invocation timestamp.

EXECUTING and its audit event must commit successfully before dispatch. An uncertain
commit response prevents dispatch; callers query using a fresh connection and do
not infer rollback. External invocation happens with **no SQLite transaction held**.
GovernedExecutor independently checks current Policy and exact approved Action.

These are point-in-time checks, not a lock across external effects. Another actor
can change incident/tool/policy after validation. There is no external fencing token
protocol, handler code attestation, distributed transaction or remote rollback.

## Approval replay guard

Existing ApprovalManager remains in-memory. This phase implements an
**execution-side durable approval reservation**, not persistence of the entire
Tool Approval request/decision/revocation lifecycle. A registered intent reserves
its approved ID permanently in this ledger, including after failure or uncertainty.
One promotion also has one reservation. Restart cannot execute a finalized intent
or reuse its approval in another intent through these APIs.

Only independently confirmed approvals exported by ExecutionBridge are registered.
Response Review, Incident Review and State Change Authorization cannot substitute.
On restart a private read-only adapter supplies the stored exact approved snapshot
to the existing Executor. It does not create or approve new requests. There is no
new durable approval revocation/expiration API; production identity and revocation
integration remain future work. Do not mix durable and legacy dispatch for the same
approval, or run separate authoritative databases for the same execution namespace.

## Outcomes and sanitized persistence

Success retains a digest of validated ToolResult, not raw Tool output. Errors retain
only exception type, never credentials or raw exception messages. The full source
plan may contain sensitive existing Evidence; restrict DB access and retention.

FAILED before the boundary proves this runner did not invoke. After the boundary,
a direct adapter ToolExecutionError without a chained underlying exception records
reported failure; it does **not** prove there were no partial effects. Wrapped
handler errors, transport failures/timeouts, cancellation and invalid output are
conservatively UNCERTAIN. An adapter must preserve causes rather than misreport a
transport ambiguity as a definitive failure. Neither FAILED nor UNCERTAIN retries.

If outcome persistence fails, ExecutionOutcomeUnknown is raised. Success might
already have committed: fresh `load(intent_id)` is the idempotent query. A remaining
EXECUTING record becomes UNCERTAIN on expired-lease recovery. A SUCCEEDED record
stays succeeded. The code never rewrites committed success because a response was
lost. If storage stays unavailable, no durable classification can be promised until
it recovers; the caller must treat the result as unknown.

## Crash windows and recovery

| Crash window | Durable state / recovery | External inference |
| --- | --- | --- |
| Intent committed | PENDING | Runner has not invoked |
| Claim committed, before boundary | Expired CLAIMED → PENDING | Runner has not invoked |
| EXECUTING committed, before call | Expired EXECUTING → UNCERTAIN | May not have invoked |
| Effect happened, success not saved | Expired EXECUTING → UNCERTAIN | Never infer failure from missing success |
| Tool failed, failure not saved | Expired EXECUTING → UNCERTAIN | Durable outcome unknown |
| Outcome transaction rolled back | EXECUTING → UNCERTAIN after expiry | No automatic retry |
| Outcome commit response lost | Fresh query yields committed outcome or EXECUTING | Do not assume rollback |

Recovery is an explicit operator call and never invokes a Tool or approves work.
A recovered PENDING intent can later be explicitly claimed; all current checks run
again. Read-only intents use the same conservative lifecycle.

## Trusted reconciliation

ReconciliationRequest binds execution ID, incident, exact lifecycle revision,
previous UNCERTAIN state, selected outcome, reason and at least one external
reference. Outcomes are confirmed_succeeded, confirmed_failed and unresolved.
The existing HumanAuthority verifies a distinct `reconcile_execution` purpose and
the complete request digest. Default DenyHumanAuthority rejects plain actor strings.
The record stores the verified subject, request and timestamp atomically with the
lifecycle change and audit. Stale/cross-incident targets fail even with confirmation.

References are operator assertions about external records, not automatically
collected Evidence or machine proof. No automatic verifier or production identity
provider is connected. Tests use a test-only confirmation adapter. All reconciled
outcomes remain non-retryable, including confirmed_failed and unresolved.

## Storage, migration and audit

Phase 4-4 creates v1 databases as before. Base governance operations support v1 and
v2; unknown future versions fail closed. ExecutionStore requires explicit migration
to v2. `migrate` uses one transaction to add execution_records and execution_events
and set user_version=2. It is idempotent at v2 and never drops/resets old tables.
Migration failure leaves v1 data/version intact. No downgrade is provided.

execution_records contains unique intent/promotion/approval coordinates, incident
foreign key, lifecycle revision/state, validated canonical payload and digest.
execution_events contains sequenced UUID events, intent foreign key, unique
intent/revision pair, payload and digest. Reads revalidate models, digests, denormalized
columns and the latest audit/state match. Every lifecycle update and event share
one transaction; ignored writes and audit failures are rejected/rolled back.

Events: intent_created, claimed, invocation_boundary, succeeded, failed, uncertain,
recovered and reconciled. Recovered events explicitly retain the resulting state.
Audit preserves the source graph, attempt token, revisions and reconciliations.
This is append-oriented API behavior, not a tamper-proof or signed ledger. A DB
administrator can replace payloads and matching digests.

Private explicit paths, 0700 directories, 0600 DB files, bounded locking, FULL
synchronous commits and commit uncertainty handling reuse Phase 4-4. Use supported
SQLite backup or an offline consistent copy. Restoring an older backup can rewind
reservations; backup rollback protection is not implemented. No automatic data
retention, encryption, replica failover or deployment is added.

## Concurrency and idempotency scope

Independent spawned Python processes compete against the same local SQLite file.
Tests assert one claimant and one invocation-boundary record for a shared intent,
independent progress for different intents, process death and restart replay denial.
Supported scope: same host, local filesystem with working SQLite locking. Not NFS,
multi-host coordination, distributed availability or external single-effect proof.

Internal idempotency prevents duplicate semantic intent registration and replay.
The existing ToolHandler/input schema has **no external idempotency-key channel**.
No unsupported argument is injected, no schema/metadata capability is fabricated.
External exactly-once side effects are not guaranteed. Future Tool-specific,
reviewed adapters may support a separate external idempotency contract.

## Security boundaries and next phase

The planner/promotion service still never dispatches or auto-approves. Registration,
claim, invocation, recovery and reconciliation are separate explicit APIs. Rejected
forgeries never become valid because they have a content hash. Tests cover changed
intent/tool/input/incident/approval, current state/metadata/policy drift, duplicate
claims, expired ownership, terminal replay and forged reconciliation.

Before production: connect real authentication/permission/revocation verification;
review Tool failure semantics and external idempotency; define durable revocation,
retention, backup rollback prevention, outcome verification and operator recovery
procedures. Existing legacy dispatch must be restricted by the composition root.
None of these operational integrations, external atomicity or distributed execution
is claimed here.
