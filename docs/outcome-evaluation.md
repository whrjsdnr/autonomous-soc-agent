# Outcome Evaluation and Operational Metrics (Phase 6-2)

Evaluation records descriptive operational facts, not correctness judgments.
Human rejection does not by itself mean the Agent was wrong.
Execution failure does not by itself mean the Agent decision was wrong.
UNKNOWN is distinct from zero and false.
Evaluation has no execution or governance authority.

## Purpose and architecture

`ExperienceEvaluator.evaluate(experience_id)` reads a stored Experience, validates
its immutable binding and necessary source records, derives objective facts and
persists an immutable `EvaluationRecord`. The evaluator version is
`soc-outcome-evaluator:v1`. No LLM, correctness classifier, scoring, recommendation,
learning, analyst feedback or improvement proposal is implemented.

One existing SQLite `BEGIN IMMEDIATE` transaction covers source validation and
canonical evaluation insertion. Evaluation never advances an orchestrator, invokes
Tools, changes an incident, creates Evidence, issues approvals or confirmations,
retries execution, or reconciles uncertainty. Existing source-model validators are
reused, including advisory policy-consistency checks; no new operational Policy
result is issued or used to grant permission.

## Binding and historical integrity

Evaluation content binds the Experience ID and full record digest, incident UUID,
workflow run UUID, trace digest and evaluator version. The evaluation ID is a
canonical content digest; storage time is outside that semantic identity.

The evaluator reads the original incident snapshot, the exact trace prefix ending
at the captured trace head, referenced registered governance records, and the
captured execution audit event/revision. References are validated by existing
model, digest and lineage primitives. Missing, foreign, corrupt or changed source
records fail closed, even if an evaluation already exists.

Normal later workflow progress or reconciliation does not change an old Experience.
An uncertain historical evaluation continues to describe the captured uncertain
execution revision; a reconciled Experience is a different input. The source
execution intent must remain unchanged. Optional `expected_incident_id` and
`expected_experience_digest` provide caller-side exact binding guards.

A superseded analysis artifact that was not independently retained may no longer
be resolvable from the current checkpoint. Evaluation then refuses rather than
reconstructing it, re-running analysis, or silently dropping the reference.

## Schema and outcome taxonomy

The immutable record contains only typed IDs, digests, enums, booleans, measured
counts and known timestamps. It preserves:

- Workflow `current_step`, `next_step`, terminal/waiting flags and `WorkflowFailure`.
- Existing `GovernanceOutcome`, including human rejection, blocked, waiting and
  review recorded. A recorded review does **not** mean an action was approved.
- Existing `HistoricalOutcome`: succeeded, failed, uncertain or not executed.

These domains are never collapsed into a single success/failure or quality score.
Flags describe recorded facts: human review/rejection, governance blocking,
preflight DENY, execution failure/uncertainty, recovery and reconciliation presence,
and assessment/Fusion presence. Fusion presence does not prove model coverage,
a correct decision, an attack, or a confirmed fact.

## Metrics and UNKNOWN

`orchestration_step_count` is the number of entries in the validated captured trace
prefix. It is not a Tool call count. `investigation_rounds_recorded` preserves the
existing recorded round counter, not a count of successful investigations.

The current source contract cannot prove an aggregate investigation count, total
Tool calls, workflow completion time or duration. These remain `None`, including
when no record is present. The known workflow start time is preserved. Duration
validation requires both trustworthy ordered timestamps and their exact delta;
the current Experience contract has no completion timestamp, so the evaluator
never fills one with the current time and never emits a duration.

`invocation_boundary_observed` describes the durable execution marker.
`execution_attempted` is true for recorded SUCCEEDED, false for a referenced
execution record without an invocation marker, and unknown otherwise. A durable
EXECUTING marker means invocation may have started; it does not count as proof of
a Tool call. A reconciliation-confirmed success is still a reported domain outcome,
not independent measurement of remote side effects or decision correctness.

`policy_deny_observed` reports stored candidate preflight DENY. `policy_blocked`
remains unknown: the existing record does not give a general typed proof that
Policy caused an actual execution block. Governance blocking is reported separately.
No reason-string guessing or re-evaluation of current policy is used to manufacture
that fact. `uncertain_observed` includes recorded uncertainty in the captured trace,
so a reconciled outcome can preserve the earlier uncertainty history.

## Persistence, determinism and migration

Call `migrate_evaluations(database)` explicitly after schema v5. The v5 → v6
migration adds only `evaluations` and its incident index. It preserves Experience,
incident, governance, confirmation, execution and checkpoint tables. Migration DDL
and schema-version change commit together; failure rolls back. The existing fresh
v1 → v2 → v3 → v4 → v5 chain remains supported, and earlier migrations become
no-ops on v6. Unsupported future versions are rejected without resetting data.

The table has unique `(experience_id, evaluator_version)` binding as well as a
primary evaluation identity. Repeated or concurrent evaluation returns the first
canonical record. Different facts for that logical binding are rejected rather
than overwritten. Neither random IDs, current time nor LLM output participates in
fact computation. A new record's `created_at` is storage metadata only.

Independent Python processes on the same local SQLite file serialize insertion
through the existing transaction boundary. This does not promise distributed
coordination or external side-effect atomicity. Commit uncertainty propagates;
callers query the store to reconcile persistence rather than retrying external work.

## Query boundary

```python
from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator, migrate_evaluations
from soc_agent.experience import ExperienceStore

migrate_evaluations(governance_store.database)
store = EvaluationStore(ExperienceStore(governance_store))
record = ExperienceEvaluator(store).evaluate(experience_id)
store.get(record.evaluation_id)
store.get_for_experience(experience_id)
store.list_for_incident(record.content.incident_id)
```

Queries validate stored evaluation content/index bindings and the originating
Experience digest. Full source-reference revalidation happens on `evaluate`,
including repeat evaluations. No HTTP endpoints or aggregate analytics were added.
No rate, accuracy, precision, recall, F1, false-positive or quality metric is produced.

## Security, privacy and limitations

No raw events, credentials, authentication material, Evidence payloads, Tool inputs,
outputs, prompts, free-form reasons or hidden reasoning are copied into evaluations.
References and facts do not become Policy, Evidence, Approval or future authority.
Database permissions and trusted-source assumptions remain those of persistent
governance. Canonical hashes are not signatures and do not make SQLite tamper-proof
against a database administrator who can rewrite all records and digests.

This is a local historical measurement layer, not production authentication,
a correctness evaluator or distributed analytics infrastructure. Phase 6-3 may
introduce separately attributed analyst feedback; it must not reinterpret these
facts as automatic correctness labels or automatic execution authority.

## Validation

Focused tests reuse existing Experience/runtime fixtures and test-only human
providers and Tools. They cover outcomes, UNKNOWN/timing, source binding and
corruption, immutable history after reconciliation, forbidden authority operations,
restart/idempotency, independent-process insertion, migration preservation/rollback
and commit-response loss. No new saved-model E2E or production provider is added.
Validation results: focused tests **22 passed**; related regression **518 passed,
exit 0**; full suite **1,971 passed, exit 0** (498.96 seconds). The full suite was
run once after focused and regression tests passed.
