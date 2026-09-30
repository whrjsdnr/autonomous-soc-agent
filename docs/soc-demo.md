# Phase 5-5: authentication input and governed demo

Demo events are synthetic.
Demo response tools do not modify real systems.
The demo does not bypass production governance.
External events are not automatically confirmed Evidence.
`severity_hint` is not severity authority.

## Architecture

`POST /events` → validated source report → durable ingestion receipt + empty Incident
→ existing workflow/start/step → read-only synthetic report Tool → Evidence of what
that source **reported** → authentication feature extraction → optional packaged
inference/Fusion → scripted demo assessment → existing Decision → human governance
→ explicit proposal/promotion → independent exact Tool Approval → durable executor
→ simulated outcome → EVALUATE/COMPLETE and actual runtime trace.

The existing runtime determines routing. Missing evidence triggers investigation;
additional investigation can return to PLAN. Repeated identical investigation hits
its existing loop guard and waits for a human. We do not alter trace entries to
force a particular narrative. Workflow COMPLETE is not Incident CLOSED: Incident
status/severity remain governed separately.

## Input contract and provenance

`SOCEvent` in `soc_agent.ingestion.models` accepts:

- UUID `event_id`, `event_type: authentication`, bounded `source`, `occurred_at`;
- bounded reference strings `subject` and `resource`;
- optional existing-enum `severity_hint`, explicit boolean `synthetic`;
- `attributes.attempts`: 1–256 existing `AuthenticationEvent` records, each with
  `event_id`, `event_time`, `account_id`, `authentication_result` (success/failure),
  and `source_identifier`.

Attempt identities must be unique, accounts must match the envelope subject, and
attempt timestamps cannot follow the envelope timestamp. All levels reject unknown
fields. There is no unrestricted attributes dictionary or raw log/credential field.
Only references should be submitted, never credentials disguised as reference values;
this schema is not a general-purpose secret detector or log redaction service.
The existing API body-size bound and authentication/access-policy checks still apply.

The stored receipt preserves the canonical event, canonical digest, Incident ID,
received timestamp and `authentication-ingestion:v1`. Original HTTP bytes and
credentials are not retained. Source strings and the synthetic flag are claims,
not authenticated proof of real login activity. Ingestion creates no Evidence,
Observation, Hypothesis, workflow, approval or model prediction.

`authentication_records` reuses `authentication_record` and produces stable,
Incident-bound stream references with **no Evidence IDs**. It does not synthesize
extra attempts from a count. `AuthenticationWindowExtractor` supplies existing
five-minute features. Models and Fusion remain derived analysis, never Evidence.

## Persistence and event replay

Explicit `migrate_ingestion(store)` installs an optional ingestion extension v1
(`soc_ingestion_schema`, `soc_events`) in the existing governance SQLite database.
The main governance/checkpoint schema remains v4. Existing tables are not reset or
relabelled. Unknown extension versions and unversioned existing event tables are
rejected. Migration uses the existing transaction helper.

Incident registration was factored into the existing `GovernanceSession.register`
so public `SQLiteGovernanceStore.register` and ingestion share exactly the same
registration validation, initial snapshot and audit write. Ingestion stores these
and the event receipt in one `BEGIN IMMEDIATE` transaction. An event INSERT failure
rolls all of them back.

One globally unique envelope event ID maps to one Incident in this store. Same ID
and canonical content returns that Incident with `duplicate: true`; conflicting
content returns HTTP 409. Normalized timestamps are canonicalized; attempt ordering
is preserved. There is no cross-event account correlation or multi-incident merge.
A unique key and SQLite write transaction serialize independent-process duplicates.
Receipt deserialization validates models and digest/column bindings. Restart replay
returns the retained Incident. Ambiguous commit handling remains fail closed; clients
must query/reconcile, never infer that a missing response means rollback.

These are local SQLite replay guarantees, not distributed exactly-once ingestion
or execution. Administrative rewriting of the database is not prevented cryptographically.

## Tools and analysis

`read_demo_authentication` is SYSTEM_READ/READ_ONLY. It accepts only reports labelled
synthetic from `synthetic-demo`, with allow-listed demo subjects. The Tool output
states `synthetic_source_report_not_verified_login_activity` and includes source,
event identity, occurrence time, digest/version and reported success/failure counts.
Only the existing investigation collector turns this retrieval result into Evidence.
It does not independently verify the source's claim.

`disable_demo_account` is SYSTEM_WRITE/HIGH and accepts only `demo-alice` or
`demo-bob`. Its deterministic result is `simulated: true`,
`real_system_modified: false`, `outcome: would_disable_demo_identity`. It invokes no
shell, subprocess, network, real account API or destructive filesystem operation.
Successful durable execution means this simulation returned, not that any real
account was disabled. Production destructive Tools are not added.

`DemoLLM` is a clearly labelled **scripted fixture**, not an actual LLM or a new ML
classifier. Its advisory severity distinguishes repeated reported failures from the
benign fixture; confidence is fixed at zero and no observations/hypotheses are
invented. It never changes Incident severity. Authentication model inference is
optional: without an explicitly supplied package, Fusion records `not_run`, never a
substitute normal prediction. With a pinned package, the existing packaged adapter
runs unchanged; real prediction values are not adjusted for the demo.

## Reproducible CLI

From the repository root:

```bash
demo_dir=$(mktemp -d /tmp/soc-auth-demo.XXXXXX)
UV_CACHE_DIR=/tmp/soc-network-ai-uv-cache uv run --offline \
  python -m soc_agent.demo.authentication \
  --database "$demo_dir/demo.sqlite" \
  --event examples/authentication/suspicious.json
```

The database path must be absolute and its existing parent private (0700). New
files use existing SQLite permissions. Repeating the command with the **same** path
reads the existing workflow instead of resetting analysis. Interrupted active claims
remain blocked under the existing checkpoint contract; this CLI does not steal claims.

To use the repository's already saved synthetic authentication package, add:

```text
--auth-package tests/fixtures/security_ai_packages/authentication_anomaly
--manifest-digest aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6
```

No training is performed. This package is a synthetic fixture, not an operationally
validated detector. Automated tests do not add another saved-model E2E suite.
The saved-package CLI was manually smoke-tested through the human pause boundary.

Other fixtures under `examples/authentication/` are `benign.json`, `malformed.json`,
`duplicate.json`, and `conflict.json`. All identifiers/IPs are synthetic. Duplicate
and conflicting files deliberately reuse the suspicious event identity. The malformed
fixture contains an explicitly invalid credential-named field with a non-credential
placeholder; ingestion rejects it rather than storing it.

The CLI calls the actual ASGI app in-process; it is not an HTTP server. It prints
Incident ID, actual current/next steps, reason, human-wait flag and trace length.
It uses a CLI-local synthetic **observer only** identity with no confirmation
capability. All approving domain authorities retain their default deny behavior.
The observer is not selected by production application composition.

Typical suspicious output follows OBSERVE → PLAN → ROUTE → ANALYZE → DECIDE → PLAN
(loop guard) → WAITING_FOR_HUMAN. The CLI stops there and does not manufacture review,
confirmation, promotion or approval. It does not claim to finish a governed action.

## Human continuation and recovery

For continuation, an explicitly configured API service must reopen the same store
and supply the existing provider/RBAC/durable-confirmation authority, as described
in `soc-agent-api.md`. Use review-requests/reviews, workflow/resume, advisory
candidates, response-review-requests/response-reviews, promotions, approval-requests
and approvals. Each human confirmation binds the exact purpose and digest. Resume
with exact references/revision, then explicitly request `execute: true` at ACT.
The API and runtime do not grant authority on an administrator string or approved flag.

Tests use the existing test-only identity provider, RBAC and SQLite confirmation
consumer to verify this continuation through the real runtime/bridge/durable executor.
READ_ONLY and WRITE paths complete; WRITE waits without exact approval. Forged,
foreign and stale approval references are rejected. Confirmations are not reusable.
Neither Incident Review nor State Authorization substitutes for Tool Approval.

Cached analysis and trace survive reopening the store and rebuilding the service.
Pre-intent response review/promotion and pending Tool Approval retain their existing
process-local limitation; they must be explicitly re-established when unavailable.
Durable invocation uncertainty survives restart as RECOVER. Recovery classifies an
expired EXECUTING record as UNCERTAIN; neither state permits automatic retry.
Trusted reconciliation is still required through the existing API/domain boundary.
SQLite state and external Tool effects are not one atomic transaction; no exactly-once
external execution or tamper-proof audit is claimed.

## Verification scope and limitations

Focused tests cover contract rejection, provenance/features, unchanged severity and
empty ingestion Evidence, replay/conflict, independent-process races, transaction
rollback, extension version rejection, benign/WRITE lifecycle, human wait/resume,
allow-list rejection, stale/foreign/forged authority, real trace, restart and
UNCERTAIN no-retry. Existing API, runtime, governance, persistence and durable tests
are run as regression before a single full-suite run.

No vendor connector, production authentication, hosted server, background worker,
real account action, external SIEM/SOAR or new model training is implemented. The
demo reader intentionally refuses non-demo sources; real source verification and
resource-scoped investigation adapters remain future work. Event schema validation
alone does not establish authenticity or a confirmed attack.

### Executed validation

- Focused Phase 5-5 tests: **21 passed**, exit 0.
- Related runtime/API/governance/persistence/durable regression: **474 passed**, exit 0.
- Single full pytest run: **1,926 passed**, exit 0 (470.28 seconds), from baseline 1,905.
- CLI smoke checks: no-package and explicitly pinned saved authentication package both
  reached the existing human pause boundary; no response execution or approval occurred.
