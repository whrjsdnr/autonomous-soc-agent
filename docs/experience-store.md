# Durable Experience Store (Phase 6-1)

Experience is historical data, not authority.
Past approval does not authorize future action.
Experience persistence failure must not cause external action retry.
Experience records do not become Evidence for another Incident.

## Purpose and architecture

This phase implements explicit capture, SQLite storage and exact-ID queries only.
It does not implement evaluation, scoring, similarity search, learning, recommendations
or improvement proposals. Phase 6-2 and Phase 7 may consume these historical records;
they must still use the original governance boundaries for any future action.

`ExperienceCaptureService` reads the authoritative incident, workflow checkpoint and
trace, registered human review graph, and (when present) durable execution ledger.
It verifies their bindings and inserts a reference-only immutable `Experience` in
one existing `GovernanceDatabase` write transaction. It never advances a workflow,
invokes a Tool, issues human authority, changes the incident, or reconciles execution.
Existing nested domain validators are reused, including the advisory model's
policy-consistency validation; capture makes no new operational policy decision.

## Schema and provenance

`Experience.content` includes its version (`experience:v1`), incident UUID,
repository/revision/full-state fingerprint, incident status and severity, workflow
run UUID, trace head and digest, step sequence, cursor and workflow flags/failure.
Typed references contain immutable IDs and content digests for available Evidence,
Observation, Hypothesis, assessment, decision, Fusion and signals, investigation,
review, state authorization, response plan/proposal, promotion, Tool Approval,
execution intent/record and last execution audit event.

These are references, not copies of the authority-bearing objects. Model references
remain separate from Evidence references. Human and response review dispositions,
stored policy preflight decisions, execution lifecycle/revision, and reconciliation
outcome retain their separate meanings.

Capture checks the current authoritative snapshot against the checkpoint. A stale
checkpoint, active/interrupted workflow claim, corrupt payload, invalid reference,
or foreign incident/run fails closed. Review references must resolve through the
registered governance graph. Execution provenance must match the checkpoint's exact
plan, promotion, approval and snapshot. Bare process-local promotion/approval IDs
without a durable execution intent cannot be authenticated after restart: capture
refuses those checkpoints rather than representing them as verified authority.

## Outcomes and timing

The workflow cursor, terminal/waiting flags and failure category are retained
separately from `governance_outcome` and `execution_outcome`.

- A completed workflow is not automatically successful execution.
- Human rejection is `human_rejected`, with execution `not_executed` when absent.
- Governance blocking is `blocked`; it is not an execution failure.
- Waiting snapshots are explicitly nonterminal historical samples.
- Durable `FAILED` and `UNCERTAIN` remain distinct.
- `EXECUTING` is conservatively summarized as uncertain because invocation may have
  started; the actual lifecycle is also retained. Capture does not modify it.
- A subsequent trusted reconciliation produces a new historical content identity;
  the earlier uncertain record remains unchanged. Capture itself cannot reconcile.

Measured metrics are trace entry count, recorded investigation rounds and checkpoint
creation time. Trace entries are not Tool calls. Total Tool invocation count,
workflow completion time and elapsed duration are deliberately null because the
existing records do not reliably establish these aggregate metrics. No quality,
confidence, risk or success-probability score is invented.

## Persistence, migration and queries

Explicitly call `migrate_experiences(database)` after the existing v1 → v2 → v3 → v4
migration chain. It adds schema v5's `experiences` table and incident index. Existing
incident, governance, execution, confirmation, ingestion and checkpoint records are
not rewritten. DDL and version update commit together; failure rolls back. Unknown
versions are rejected, never reset. Existing components accept the additive v5
schema without changing their authority contracts.

```python
from soc_agent.experience import (
    ExperienceCaptureService,
    ExperienceStore,
    migrate_experiences,
)

migrate_experiences(governance_store.database)
store = ExperienceStore(governance_store)
capture = ExperienceCaptureService(store)
record = capture.capture(incident_id)  # optionally supply expected_run_id / expected_snapshot
same_record = store.get(record.experience_id)
incident_history = store.list_for_incident(incident_id)
```

There is no new HTTP endpoint or automatic runtime hook in this phase. An application
must explicitly call this service. Querying historical data does not require that
the incident still be at the captured snapshot. Queries validate stored model,
canonical digest and indexed identity bindings. No arbitrary update API is exposed.

## Idempotency, concurrency and restart

The semantic content digest is the experience identity; capture time is excluded.
Repeated capture returns the first stored record. Terminal polling entries after
the first terminal trace entry are excluded so polling alone does not create new
terminal experiences. Changed source outcomes/references produce a new historical
record. Conflicting content under an existing identity fails validation.

`BEGIN IMMEDIATE`, primary-key uniqueness and source reads plus insertion in one
transaction serialize independent processes on the same local SQLite file. Both
callers may receive the same canonical record; only one row is inserted. This is
not a distributed execution guarantee. Restart queries require no in-memory
approval reconstruction. Commit errors propagate; a lost commit response requires
query/reconfirmation of the historical record, never rerunning external execution.

## Privacy and security limitations

Only typed identifiers, hashes, enums, counts and known timestamps are persisted.
Raw events, Tool inputs/results, summaries, prompts, reviewer credentials, tokens,
secrets and hidden reasoning are not copied. Reasons remain in the original records;
Experience uses their typed failure categories and digests instead of free text.

SQLite file/directory permissions and trust assumptions remain those of persistent
governance. Hashes detect accidental/content mismatch; they are not signatures and
cannot defend against an attacker who controls the DB and rewrites all source
records and hashes. This is not tamper-proof audit, production authentication,
distributed storage, or atomic DB plus external side effects. Historical captures
with process-local-only promotion provenance are intentionally unsupported.

## Validation

Focused tests cover real runtime success, failure, uncertainty, waiting/rejection,
reconciliation, reference integrity, stale snapshots, no-authority operations,
idempotent restart queries, independent Python-process races, migration preservation
and rollback, and commit-response loss. Existing test-only human authorities and
mock Tools are reused; no new saved-model E2E or production identity provider is added.
Validation results: focused Experience tests **23 passed**; related regression
**495 passed, exit 0**; full suite **1,949 passed, exit 0** (492.76 seconds).
The full suite was run once after focused and regression tests passed.
