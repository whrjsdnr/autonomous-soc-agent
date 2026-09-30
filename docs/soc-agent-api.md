# SOC Agent Application/API (Phase 5-4)

The API exposes orchestration; it does not grant authority.
The Orchestrator coordinates authority; it does not own authority.

## Composition and startup

`SOCApplication` is a small ASGI callable. No HTTP framework, server dependency,
module-level singleton, default database location or background worker is added.
The application receives an explicit service factory. ASGI lifespan startup calls
that factory; embedding without lifespan initializes it on the first authorized
request. Startup errors expose only `Startup failed`.

Use `api.startup.open_store(Path(...), create=False)` to open an existing database
and explicitly apply the existing execution, confirmation and checkpoint migrations
(up to schema v4). Initial creation requires `create=True`; existing data is never
reset. `ApplicationService` requires this durable store, a **fresh SOCRuntime
factory**, persistent review service, promotion service, execution bridge, durable
execution store and optional reconciliation authority. Existing models, registry,
policy, LLM and adapters are supplied by trusted composition. The runtime factory
must bind that same checkpoint repository; memory-only runtimes are rejected.
No new settings subsystem or environment-selected test adapter exists.

An ASGI server may host the callable externally. This phase does not install or
configure an operational server, TLS, login, deployment or identity provider.

## HTTP contracts

All routes require provider-verified authentication and a configured, trusted
incident-scoped `AccessPolicy`. JSON request models reject unknown fields. UUIDs
are validated. Request bodies are limited to 64 KiB. Credentials are accepted only
as one `Authorization: Bearer <opaque credential>` header, forwarded to existing
trusted providers; they are never logged or persisted by this layer. Responses use
`Cache-Control: no-store`.

Paths below are relative to `/incidents/{incident_id}` unless stated otherwise.

| Method / path | Operation |
| --- | --- |
| POST `/incidents` | Register a new Incident with caller-selected UUID; only `incident_id` accepted |
| GET base path | Read authoritative state and anchor |
| POST `/workflow/start` | Create the initial durable workflow checkpoint; empty body |
| POST `/workflow/step` | Advance exactly one runtime step |
| POST `/workflow/resume` | Restore and advance exactly one step, with optional human artifact references |
| GET `/workflow` | Current result, workflow ID and checkpoint revision |
| GET `/trace` | Existing immutable orchestration trace |
| GET `/artifacts` | Cached validated analysis/decision/advisory artifacts for review |
| POST `/review-requests` | Prepare existing incident review request, requiring a cached decision |
| POST `/reviews` | Record review through persistent human review service |
| POST `/response-review-requests` | Prepare response review intent for an exact proposal |
| POST `/response-reviews` | Record explicitly confirmed response review |
| POST `/promotions` | Explicitly promote a referenced response review using existing revalidation |
| POST `/approval-requests` | Explicitly create existing **pending** Tool Approval request |
| POST `/approvals` | Submit independent exact human Tool Approval through ExecutionBridge |
| POST `/reconciliation` | Forward existing ReconciliationRequest to the durable execution store |

There is no arbitrary state patch. Creating an Incident sets domain defaults;
status, severity, observations, Evidence and approvals cannot be injected in the
create body. Initial events/Evidence are ingested through existing trusted
composition/investigation, not a newly introduced raw-event authority endpoint.

## Step-based lifecycle and example

1. POST `/incidents` with `{"incident_id":"<uuid>"}`.
2. POST `.../workflow/start` with `{}`.
3. Read the response's `workflow_id` and `checkpoint_revision`. Submit
   `{"run_id":"<workflow UUID>","expected_revision":0}` to `.../workflow/step`.
4. Repeat explicit steps, using the returned revision. Each request restores the
   existing checkpoint, revalidates sources and advances at most one step.
5. When `waiting_for_human` is true, prepare the appropriate review request and
   obtain external request-specific confirmation. POST `/reviews` with
   `request_id`, `reviewer_id`, `outcome` and `reason`; the service verifies that
   reviewer against authenticated confirmation, never trusts the string itself.
6. Resume with the resulting `review_id`. Supply existing `CandidateIntent`
   values in `candidates` when proposing responses; the existing planner validates
   registry/schema/grounding and policy. Inspect `/artifacts` for proposal IDs.
7. Explicitly prepare/confirm response review (`proposal_id`, `reviewer_id`,
   `disposition`, `reason`, `blocker_responses`), then POST `/promotions` with its
   `review_id`. Resume with `promoted_id`.
8. WRITE remains waiting without exact Tool Approval. Prepare `/approval-requests`
   with `promoted_id` and `reason`; confirm via `/approvals` with `promoted_id` and
   `approval_id`. Resume with these references.
9. ACT requires an explicit step with `execute:true`. Only the existing durable
   executor invokes the Tool, after execution-time validation. No human endpoint
   advances the workflow or invokes Tools as a side effect.
10. EVALUATE leads to COMPLETE or an explicit failed outcome. UNCERTAIN returns a
    normal workflow response with `next_step: recover`; it is not success or an
    automatic retry. External trusted reconciliation and subsequent explicit
    resume are required.

Workflow responses preserve `incident_id`, `current_step`, `next_step`, `reason`,
`references`, `waiting_for_human`, `terminal`, `failure`, plus `workflow_id` and
`checkpoint_revision`. No risk score or transport-specific interpretation is added.

## Identity and governance

`AuthenticationProvider` verifies credentials; unconfigured authentication or API
access policy denies all requests. API access authorization does not replace human
operation RBAC. Compose the existing `ProviderHumanAuthority`,
`RBACPermissionVerifier` and `SQLiteConfirmationConsumer` into review, promotion,
bridge and reconciliation dependencies. The existing provider must verify human
intent for the exact purpose/digest; the API never calls provider confirmation to
manufacture intent, issues identities, assigns roles or generates confirmations.

Preparation endpoints return requests, not authority. Response review is not Tool
Approval. State Change Authorization is not accepted in place of an approval ID.
Policy DENY remains effective, even for an authenticated administrator. READ_ONLY
uses existing policy; WRITE retains exact independent Tool Approval and durable
execution replay protection. Production identity and incident access policies must
be supplied by deployment; test providers and permissive test access fixtures live
only under tests and are never selected automatically.

## Replay, checkpoint and restart

`run_id` and `expected_revision` are mandatory for every step/resume. The service
checks the durable cursor before and after fresh restore; the existing runtime
claims that cursor with atomic SQLite CAS **before** advancing. Duplicate requests
are rejected rather than silently applied at the next revision. Concurrent losers
receive conflict; there is no automatic conflict retry. Duplicate start is rejected.
Confirmation consumption and approval replay rules remain in the existing services.
Pending request creation is not approval and may create another pending request
on retry; clients should retain request identities and explicitly query/reconcile
uncertain outcomes instead of blindly retrying writes.

Restart preserves checkpoints, trace, completed analysis, human waiting and
UNCERTAIN/RECOVER. Checkpoints grant no authority. Before durable intent creation,
response review/promotion and pending Tool Approval remain process-local, as in
Phase 4-6. Missing live authority after restart requires an explicit fresh human
path. Existing durable execution intent supports restored ACT; all invocation-time
checks still apply. Interrupted workflow claims require operator investigation;
this API does not clear or steal them.

## Errors and limitations

- 401: missing/unverified/expired identity or no configured authentication.
- 403: API access denied, human authorization denied, or execution policy blocked.
- 404: missing or foreign incident-scoped resource.
- 409: stale revision, duplicate start, active claim, stale snapshot or replay.
- 422: invalid JSON/model/UUID or domain input validation failure.
- 413: body limit exceeded; 405: unsupported method.
- 503: persistence unavailable or commit outcome unknown; query/reconcile before retry.
- 500: unexpected internal failure; raw exceptions, credentials and stack traces are omitted.

Workflow FAILED/UNCERTAIN are domain outcomes within workflow JSON, not flattened
into transport errors. Runtime failure reasons use the existing sanitized categories.

SQLite supports cooperating processes on a local filesystem. The small ASGI adapter
uses synchronous local service calls and makes no throughput or distributed service
guarantee. Rate limits, operational access policy, TLS, server supervision, production
identity and deployment remain external. There is no exactly-once external execution:
SQLite state and external Tool side effects are not one atomic transaction.

Tests exercise the ASGI callable directly with existing mock Tools/LLM and test-only
provider/RBAC/durable confirmation adapters. No new saved-model E2E is introduced.
Final focused, regression and full-suite results are reported with the change.

## Verification results

- New Application/ASGI tests: **19 passed**, exit 0.
- Related runtime/checkpoint/governance/persistence/durable regression: **455 passed**, exit 0.
- Single full pytest run: **1,905 passed**, exit 0 (426.90 seconds).
- Baseline: 1,886 tests; no existing tests were removed or weakened.
