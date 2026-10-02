# Improvement Dataset (Phase 6-4)

Improvement Dataset is an offline historical artifact, not runtime authority.

Dataset membership does not authorize future action.

Analyst disagreement is preserved, not automatically resolved.

INCONCLUSIVE feedback is not converted into a correctness label.

Dataset generation does not modify prompts, policies, models, or runtime behavior.

## Explicit eligibility

The caller supplies evaluation IDs to
`ImprovementDatasetBuilder(store).build(evaluation_ids)`. The builder reads durable
Experience, Evaluation, AnalystFeedback, confirmation receipts, audit bindings,
and their historical source records inside a single SQLite transaction.

No feedback excludes an evaluation as NO_FEEDBACK. Conflicting conclusive
verdicts, FALSE_POSITIVE/FALSE_NEGATIVE, or
UNNECESSARY_INVESTIGATION/MISSED_INVESTIGATION diagnostic meanings exclude it as
ANALYST_DISAGREEMENT. Any INCONCLUSIVE judgment excludes supervised membership.
Otherwise the common verdict and union of compatible labels are retained.
Every feedback reference, including disagreement and inconclusive feedback,
is preserved in the manifest's selection. There is no majority vote.

Only overall scope is supported in v1. UNSUPPORTED_SCOPE is reserved for ordinary
selection exclusion when source schemas support additional scopes; an unsupported
scope in a current v1 durable feedback record violates its schema and fails integrity
validation instead.

## Exclusion versus integrity failure

Exclusions are valid historical judgments with no supervised sample. Missing,
forged, cross-incident, mismatched, or corrupt records and digests raise
StoredDataError (SQLite structural failures raise StorageError). They abort the
transaction, never become ordinary excluded samples. Queries and export also verify
pinned records, manifest bindings and membership. Digests detect inconsistent
tampering; they are not signatures protecting against an attacker able to rewrite
the entire database and all bindings.

## Immutable references and manifest

Samples are frozen Pydantic models with schema version, incident identity,
Experience/Evaluation IDs and digests, canonically ordered feedback IDs and digests,
overall verdict, compatible labels, workflow/governance/execution facts, and factual
operational context. Full metrics remain available through the pinned Evaluation.
Unknown investigation/tool counts remain null rather than fabricated zeroes.

The manifest includes a separately validated source_snapshot_id, the canonical
content digest of ordered source bindings. The immutable manifest contains exact source bindings for eligible and excluded
evaluations, ordered sample references and factual counts. Evaluation IDs,
feedback IDs and sample IDs have canonical ordering independent of DB iteration or
caller order. Versions are explicit:

- builder: soc-improvement-dataset-builder:v1
- eligibility: soc-improvement-eligibility:v1
- sample: improvement-sample:v1
- dataset: improvement-dataset:v1

Dataset ID, dataset version and manifest digest are the canonical manifest's
SHA-256 content identity. Dataset version is a content version, not an incrementing
sequence. created_at is persistence metadata outside logical manifest identity.
Equal source snapshots and versions produce equal logical datasets.

## Snapshot and explicit rebuild

A snapshot pins precisely the feedback present during the build. Adding feedback
does not change previous membership, manifests, digests or exports. Queries verify
only pinned feedback while checking immutable source integrity. A subsequent explicit
build captures current feedback: unchanged sources return the existing dataset,
changed sources create a new content version. Old snapshots are never overwritten.
Source corruption makes affected snapshots unreadable rather than silently revising them.

BEGIN IMMEDIATE serializes competing builds across independent processes.
Primary keys and membership constraints prevent duplicate logical datasets; an
existing conflicting identity fails closed. This is transactional idempotency,
not an exactly-once execution guarantee.

## Persistence and queries

Apply the existing explicit migrations through feedback v7, then
`migrate_datasets(database)` for additive v7 to v8. No earlier tables are replaced.
Failed migration rolls back and future schema versions are rejected.

`get_dataset`, `list_datasets`, `get_sample`, and `list_samples(dataset_id)`
are explicit offline queries. They remain usable after process restart.
No runtime component imports or automatically consumes dataset context.

## Export, privacy and statistics

`export_json(dataset_id)` returns canonical JSON in manifest membership order,
including schema/builder/eligibility metadata and source references. It excludes
creation-time metadata, feedback notes, actor sessions, credentials, tokens,
raw incident payloads, prompts and chain of thought. Export is read-only.

`statistics(dataset_id)` provides only sample, correct, incorrect, false-positive
label, false-negative label, exclusion and disagreement counts. These are historical
facts, not accuracy, precision, recall, F1 or quality/improvement scores.

## Authority and Phase 7 boundary

The builder only adds dataset/sample/membership rows. It does not mutate IncidentState,
Evidence, Evaluation, Feedback, confirmation, policy or approval records. It calls no
LLM, assessor, human review, tool, executor, reconciliation or runtime orchestrator.

Training, automatic learning, reflection, prompt changes, policy changes and runtime
adaptation are outside Phase 6-4. Any future Phase 7 use requires its own explicit
design and governed authorization; this dataset grants none.
