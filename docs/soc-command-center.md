# SOC Command Center — Phase 8-1

The Command Center is an authenticated, read-only observation surface. Its Overview
connects incidents, retained workflow cursors, human waiting states and model-derived
signals. It does not grant governance authority or advance an agent.

## Running / composition

The existing `soc_agent.api.SOCApplication` now serves:

- `GET /dashboard`: server-rendered HTML, embedded local CSS, manual refresh.
- `GET /api/dashboard/overview`: the same immutable `DashboardOverview` as JSON.

No dependencies, Node tooling, JavaScript, server, IdP or demo records are added.
Keep the existing explicit `ApplicationService` composition described in
[SOC Agent API](soc-agent-api.md). The composed ASGI callable can be hosted by the
user's existing ASGI server. Neither route invokes `runtime_factory` or a model.
There is intentionally no public module-level app with development credentials.

Both routes require one `Authorization: Bearer <opaque credential>` header verified
by the configured `AuthenticationProvider`, and trusted `AccessPolicy` permission
`GET:dashboard` at the aggregate scope. For each included incident the policy must
also permit existing operations `GET:`, `GET:workflow` and `GET:artifacts` at that
incident ID. A denied incident is excluded from every count, signal and activity.
A deployment should explicitly grant read access to intended users in its existing
access policy; this phase does not introduce another RBAC/identity system.

Normal browser navigation does not supply a Bearer header by itself. Browser hosting
therefore requires the existing authenticated gateway/header-injection setup to
supply the provider-verifiable header on **every** navigation, including Refresh.
A bare browser without that setup receives 401. No token query parameters, browser
storage, login form, cookie identity trust or authentication bypass is introduced.
For an already hosted ASGI composition, the existing credential can also be used
with an HTTP client to request either route; no new dashboard-specific credential
is issued. Do not put credentials in repository files or URLs.

## Architecture and snapshot

`HTML renderer → ApplicationService.dashboard_overview → persistence snapshot reader`

The persistence reader uses one `GovernanceDatabase.transaction(write=False)` with
SQLite `query_only=ON`. It validates current IncidentState fingerprints and checkpoint
payload digests/identity bindings. The application projects those records into frozen
DTOs. Presentation does not open SQLite or receive raw event/Evidence payloads.

Reads do not restore runtime state, replay complete governance/source graphs, consume
confirmations, query model APIs, run inference, execute tools or change checkpoints,
incidents, approvals or improvement active versions. Schema remains **v14**; no
migration or durable dashboard cache is required. Existing checkpoint-capable databases
(v4 onward) can also be observed through the same application composition.

## Overview semantics

All counts refer to the same **authorized snapshot**, not an organization-wide claim.

| Field | Definition |
| --- | --- |
| System | `UNKNOWN`: no health probe contract exists. A successful read is not proof of system health. |
| Active incidents | Current IncidentState status is not `closed`. State severity is labeled explicitly; advisory assessment severity is not substituted. |
| Workflows in progress | Retained checkpoint has `terminal == false`, including human waits. |
| Human action required | One entry per checkpoint with `waiting_for_human` or an outstanding claim. This is a workflow-scoped summary, not a census of all approval queues. |
| Security signals | Unique signal IDs in the retained `FusionAssessmentResult` contexts, across authorized checkpoints. Zero means zero in this source, not absence of threats or unpersisted signals. |
| Active table | All authorized non-closed incidents; missing workflow shows `UNKNOWN`. |
| Workflow | Exact last recorded step and next cursor. Other stages are not assumed complete. A claim can mean active or interrupted work and is not automatically retried. |
| Signals | Latest available contribution per Network/Authentication domain, chosen by source timestamp and artifact ID; Fusion shows agreement separately from confidence. |
| Recent activity | Actual incident creation timestamp and latest checkpoint update timestamp, newest first, stable tie ordering, capped at 20. Trace entries have no event timestamps, so no synthetic per-step time is assigned. |

Human categories remain explicit: Incident Review, response candidate input,
Response Review / response promotion, Tool Approval, execution reconciliation, and
other workflow input/dispatch. They describe retained workflow requirements rather
than proving a current pending request exists. Improvement Review and independent
queues are not included because no cheap application-level aggregate query exists.

Posture is deterministic, in priority order:

1. Outstanding workflow claim or `next_step == recover`: `RECOVERY REQUIRED`.
2. Any retained human wait: `ACTION REQUIRED`.
3. Any non-terminal workflow: `INVESTIGATING`.
4. Otherwise: `UNKNOWN`.

This is workflow posture, never a numerical security/risk score. A stale checkpoint
can retain a human wait after a review is submitted until the runtime is explicitly
resumed. The checkpoint timestamp and this scope are displayed/documented.

## AI, provenance and UNKNOWN

Network and Authentication cards display stored contribution decisions, model kind,
model reference, source-time watermark, incident/run/artifact identity and score
semantics. Fusion displays its agreement and coverage plus retained limitations.
No scores are converted to an attack probability. IsolationForest anomaly rank is
not attack probability; Fusion agreement is not statistical confidence. Confidence
stays `UNKNOWN`. Missing artifacts display `UNKNOWN` and an unavailable timestamp.
No Endpoint, Process or File AI capability is implied.

Signals only available outside retained Fusion assessments are currently unavailable
to this overview. No data is inferred from model names, raw Evidence text or incident
severity. Provenance is analytical lineage, not verified observed Evidence.

## Rendering and interaction safety

All backend strings are HTML-escaped, including attributes, reasons and model text.
No raw `innerHTML`, scripts, external fonts, images or third-party assets are used.
Responses have `Cache-Control: no-store`, `nosniff`, `no-referrer`, and a CSP allowing
only the hash-pinned embedded stylesheet (`default-src 'none'`, no frames/forms).
Dashboard routes accept GET only. No Approve/Reject/Execute/Retry/Reconcile or
Promotion/Rollback controls are present. Existing separate API governance remains
unchanged; query access never creates action authorization.

The desktop grid supports 1366/1920 widths; narrower layouts wrap cards and sidebar.
Tables scroll locally, full IDs remain in title attributes, native links/details are
keyboard accessible, and badges include text rather than relying on color.
Refresh is a normal authenticated page navigation; there is no polling/background
work. Empty incidents, workflows, human waits, signals and activity have explicit
empty states. No fake demo data hides missing artifacts.

## Verification and next phases

```bash
uv run --offline pytest -q tests/integration/api/test_dashboard.py
uv run --offline ruff check .
uv run --offline ruff format --check .
```

Tests cover snapshot consistency, deterministic summaries, authorization and object
filtering, XSS, real durable workflow waiting/claim states, signal provenance,
read-only database preservation and HTML structure. No browser automation or live LLM
is required. Responsive rules are structurally checked, not pixel-verified.

Foundation limitations: current records are decoded for every visible incident;
large-fleet pagination/materialized read models remain future work. There is no
health probe, global governance queue, complete timestamped trace timeline or login
UI. Existing demo ingestion can supply genuine demo artifacts without changing the
Dashboard query path; see [SOC demo](soc-demo.md).

Phase 8-2 adds incident detail and richer workflow visualization. Phase 8-3 may add
separate, explicitly governed human-action UX. Promotion/Rollback UI, deployment,
new models, model calls and new governance subsystems remain out of scope here.

## Incident Detail — Phase 8-2

The incident detail view is a read-only projection of durable SOC state.

- `GET /dashboard/incidents/{incident_id}`: structured HTML detail.
- `GET /api/dashboard/incidents/{incident_id}`: immutable `IncidentDetailView` JSON.
- Overview incident IDs link to the HTML route; both navigation and Refresh require
  the same trusted Bearer-header forwarding described above. Plain browser anchors
  do not create or retain an Authorization header by themselves.

Both routes authenticate before access checks. In addition to `GET:dashboard`, the
trusted AccessPolicy must explicitly permit `GET:dashboard/incident-detail` for that
incident, and existing `GET:`, `GET:workflow`, `GET:trace`, `GET:artifacts` object reads.
The new operation protects the combined incident history view; it is not a new RBAC
or governance subsystem. Aggregate access alone cannot grant detail/history access.
Denied object reads return 403; authorized unknown incidents return 404. GET is the
only supported method. No browser token storage, query credentials or login system
is added.

### Snapshot and query sources

The existing application boundary delegates to an incident-scoped persistence reader
in one read-only SQLite transaction (`query_only=ON`). It reads authoritative state,
retained checkpoint/trace, incident-linked review/state-change records, execution
records/events and, where their schema exists, stored evaluations/feedback counts.
Current-state fingerprints, local payload digests, indexed identity bindings,
checkpoint/trace head consistency and pinned execution bindings are checked. The
reader does not restore governance issuance services, verify the complete historical
source graph, run offline evaluation or call any runtime/model/Executor.

Schema stays v14. Earlier checkpoint databases remain readable; missing optional
Outcome/Feedback tables show unavailable data rather than creating tables. Historical
Evaluation JSON is locally validated and displayed as a recorded descriptive artifact;
its entire Experience/source graph is not re-evaluated on each GET.

The top summary shows **authoritative** IncidentState status/severity, creation/update
times and revision. Cached analysis belongs to the retained workflow snapshot. A
revision/fingerprint difference is shown explicitly instead of rebinding old artifacts
to new state. Detail can include historical incident-linked execution/evaluation
records; their exact run/proposal IDs remain visible.

### Workflow and human boundary

The server derives each stage from recorded trace results and the checkpoint cursor:

- `CURRENT`: the saved next cursor, without a recorded human wait.
- `WAITING`: the saved cursor has `waiting_for_human`.
- `ADVANCED`: a trace result for that stage records a different next cursor without
  a failure. This is a transition fact, not evidence of successful Tool execution.
- `FAILED`: the latest recorded result for that stage has a non-UNCERTAIN failure,
  unless it is the current waiting cursor (the failure field is still displayed).
- `UNKNOWN`: unresolved claim, UNCERTAIN result, or a recorded self-transition
  without enough evidence to classify completion.
- `NOT OBSERVED`: no result records that stage; it is not presumed skipped.
- `TERMINAL`: the saved terminal cursor. Terminal does not mean success.

The latest cursor takes precedence over past attempts/loops. Trace details preserve
sequence, current/next step, waiting, failure and explanatory reason. Trace entries
have no event clock, so they are displayed by sequence without fabricated timestamps.
The HUMAN GOVERNANCE boundary explains that Assessment/Decision cannot replace
Incident Review, State Change Authorization, Response Action Review or Tool Approval.
An outstanding workflow claim is observed, never cleared or retried by the UI.

### Evidence, reasoning and decision

Evidence, observations, and hypotheses are intentionally displayed as different artifact classes.

Evidence cards show source-confirmed record metadata and summary, observed/collected
clocks and explicitly supplied reliability. They are not labeled universally verified
or trustworthy. Observations are evidence-supported descriptions, with links to their
actual supporting Evidence IDs. Hypotheses are unverified interpretations with their
recorded confidence; that number is not a calibrated attack probability.

Threat assessment severity is advisory and is not the incident's authoritative severity.

Assessment includes its own ID, summary, source references and retained Fusion ID.
The Decision panel shows the actual analytical outcome, rationale, investigation/
review reasons and uncertainties. IncidentDecision has no proposed state mutation
field or creation clock, so neither is invented. An advisory HIGH assessment may
coexist with authoritative INFO state, or vice versa after an actual governed change.

Investigation plans expose step/action IDs, tool names, purpose, actual step status
and returned Evidence IDs. Step permissions are `NOT AVAILABLE`: the plan does not
pin ToolMetadata. Workflow-specific strategy provenance is also `NOT AVAILABLE`:
no active registry value is read or attributed retroactively to an incident. No Tool
input, schema payload or arbitrary failure message is displayed.

Stored Network, Authentication and Fusion contexts reuse Overview interpretation:
no anomaly-to-probability or agreement-to-confidence conversion. Model-derived
context remains separate from Evidence. Missing contexts stay UNKNOWN.

### Governance, response and recovery

Separate rows show Incident Review requests/records, State Change Requests,
Authorizations and Applications. `ISSUED` authorization is not `applied`; only an
ApplicationResult reports an applied change. Pending Incident Review means no
review record exists for that request in this snapshot. Retained workflow waits can
lag an already submitted review until explicit orchestration resume.

Response Review, response promotion and Tool Approval snapshots are displayed when
preserved in a durable ExecutionIntent. Independent memory-only response review/
approval requests are not queried or portrayed as durable. Actor values are recorded
attribution; roles are unavailable and are not inferred from usernames or current RBAC.
No credential, confirmation receipt or session material is included in the DTO.

A proposed or promoted response is not displayed as executed unless durable execution evidence exists.

Response proposals retain PROPOSED/PROMOTED labels separately from execution lifecycle.
Execution shows stable action ID, intent/proposal/promotion references, actual lifecycle,
invocation/finish timestamps and recorded reconciliation. UNCERTAIN is not FAILED;
reconciliation is a distinct historical fact and does not imply automatic retry.
SUCCEEDED records a durable execution outcome, not independent verification of external
security effect. No action can be submitted from this page.

Incident-linked Outcome Evaluation shows stored descriptive execution/governance facts,
run/Experience IDs and feedback record count. No correctness verdict is generated.
No feedback schema means UNKNOWN count; an existing empty feedback relation yields a
measured zero. Feedback notes, credentials and full raw artifacts are not exposed.

### Provenance, timestamps and disclosure safety

The provenance inventory is not a causal graph. Links use explicit recorded
supporting/basis/binding IDs (Evidence→Observation/Hypothesis, source references→
Assessment, Assessment→Decision, Decision→Incident Review, Review→Response proposal,
proposal→ExecutionIntent). Unavailable references remain plain IDs instead of broken
anchors. No generic EVENT→SIGNAL→EVIDENCE chain is assumed. Signal metadata has its own
artifact provenance. Internal anchor links are created only for displayed records.

The timeline uses actual artifact timestamps, oldest first with stable tie ordering;
duplicate preserved snapshots are deduplicated. Incident creation, Evidence clocks,
reasoning/assessment creation, recorded governance, response creation/promotion,
execution events and evaluation creation can contribute. Timestamp-free requests,
Decision and trace steps receive no guessed time.

Raw Evidence `raw_data`, Tool/action/approval input, headers and secret-bearing execution
reason fields are omitted at the DTO boundary, including JSON responses. Display text
with explicit credential markers (the existing feedback rejection convention, extended
to Authorization/Cookie markers) is withheld as a whole. This is conservative basic
filtering, not a guarantee that arbitrary unmarked sensitive prose can be detected;
object-level authorization remains mandatory. All retained text is HTML/attribute
escaped, and the existing no-script/no-form CSP applies. No raw-artifact JSON viewer
or `<pre>` domain dump is added.

UNKNOWN is preserved rather than converted into a safe or successful state.

Summary, Workflow, Advisory Assessment and Human Governance appear first. Evidence,
Observations, Hypotheses and provenance are structured details below, with progressive
trace disclosure. Existing dark styles, responsive wrapping, native keyboard links,
textual badges and local table scrolling are retained.

### Verification and remaining scope

```bash
uv run --offline pytest -q tests/integration/api/test_incident_detail.py tests/integration/api/test_dashboard.py
```

Tests exercise real durable read/governance/execution contracts with deterministic
setup adapters. Detail GET itself makes no LLM, model inference, Tool, Response,
approval, confirmation, IncidentState/checkpoint or improvement-pointer mutation.
API deployment, authentication hosting, complete historical investigation retention,
pagination, independent memory-only approval queues and pinned per-workflow strategy
metadata remain future work. Large incident histories can make local decoding expensive;
there is no automatic polling. Phase 8-3 human-governance UX remains a separate phase.


## Human Governance UX — Phase 8-3

The dashboard does not grant governance authority.

Human decisions are submitted through the existing trusted governance services.

### Inbox and supported domains

`GET /dashboard/governance` lists accessible, RBAC-permitted durable pending
Incident Review and State Change Authorization requests. Immutable
`GovernanceActionView`/`GovernanceInbox` includes the exact request digest,
current/proposed state, recommendation, actual Evidence/Assessment references,
required permission and confirmation requirement. Risk and expected impact remain
UNKNOWN: these Incident request contracts do not establish them. State change
requests have no creation timestamp; none is invented. Ordering is by
incident ID, domain and request ID. Pending sources use one read transaction.
Empty inboxes contain no synthetic action. Stale snapshots are visible but disabled.

Overview and the Incident Detail Human Governance panel link to the inbox.
Completed decisions stay visible in Incident Detail rather than the pending inbox.

| Domain | UX and existing authority |
|---|---|
| Incident Review | Native form delegates to `PersistentHumanReviewService.record_review`. Actual options: acknowledged_without_authorization, additional_investigation_requested, state_change_rejected, state_change_may_be_proposed. No invented APPROVE/DEFER enum or automatic proposal. Existing ANALYST/ADMIN permission. |
| State Change Authorization | Existing typed proposal delegates to `authorize_change`. Current and proposed state remain separate. Existing APPROVER/ADMIN permission. Issues authorization; never calls `apply`. |
| Response Action Review | Read-only durable intent snapshots in Incident Detail. Pending review intents reside in `ApplicationService.response_intents`, not a durable enumerated queue. No decision UI supplied. |
| Tool Approval | Read-only durable execution-intent snapshots. Pending approval requests lack a durable inbox/query contract in this application. No decision UI supplied. |
| Durable Reconciliation | Read-only UNCERTAIN execution/reconciliation history. `ExecutionStore.reconcile` requires a human attestation request; pending attestations are not durably enumerated. No request or observation is fabricated for a button. |

Response review approval does not mean the response executed successfully.

Reconciliation does not imply automatic retry.

### Routes and two-step flow

Existing Bearer authentication and incident-object checks precede source loading.
Trusted composition must explicitly permit `GET:dashboard/governance`,
`GET:governance/{domain}` and existing object reads `GET:`, `GET:artifacts`,
`GET:dashboard/incident-detail`. POST also requires `POST:reviews` or
`POST:state-authorizations`, plus `POST:governance/{domain}/{preview|decision}`.
HTTP access permission remains separate from the domain service's RBAC.

- `GET /dashboard/governance/incidents/{incident_id}/incident-reviews/{request_id}`
- `GET /dashboard/governance/incidents/{incident_id}/state-authorizations/{request_id}`
- `POST` resource `/preview`: strict domain input and expected request digest,
  then a **non-consuming** existing confirmation lookup. Creates no record.
- `POST` resource `/decision`: pinned request digest, domain input, confirmation
  reference and exact action digest. Server reconstructs and revalidates context.
  The existing persistent service consumes confirmation and inserts the governance
  record in its transaction. No state application follows.

Native forms use no JavaScript. JSON clients can use `Accept: application/json`
on the same routes. There is no generic `/approve`. Body actor/role/permission/purpose
fields are rejected. Reviewer identity comes from the authenticated provider.
Hidden request references convey no authority; all are checked server-side.
Preview shows domain, decision, current/proposed state, basis, action digest,
existing confirmation reference and expiry. Cancel is a read. The final button
names the actual decision. Success says **Governance Decision Recorded** with
record ID/time, never threat elimination or execution.

Approval does not imply execution.

### Confirmation and trusted hosting

`ApplicationService(governance_confirmation_preview=...)` accepts an optional trusted
**read-only lookup** of an existing `HumanConfirmation` for credential, authenticated
principal and server-built `HumanActionContext`. It must read the same provider
confirmation selected by existing `confirm`; it must not issue or consume one or
interpret a click as authenticated human authority. The provider's existing explicit
human-intent flow must already establish the exact confirmation, including decision
and reason. The existing trusted context resolver must resolve the same context at
commit. There is no default adapter, provider, confirmation issuer or permissive RBAC.

Without this adapter, action pages are read-only and POST fails closed. The existing
`ProviderHumanAuthority` must have a confirmation consumer; trusted composition must
bind its SQLite consumer to the same authoritative repository. Preview checks
subject/provider/session/purpose/digest/expiry and durable consumption without
calling `provider.confirm`. Final submission still requires the existing provider
and durable consumer, including freshness/replay enforcement. Restart and process
replay protections remain those of the existing services. No UI confirmation ticket
or table is created. Schema v14 is unchanged.

Request-specific confirmations cannot be reused across governance domains.

`SOCApplication(..., dashboard_origin="https://your-trusted-host")` explicitly opts
browser POST into an exact configured origin. No trusted origin is inferred.
POST requires exact Origin/Host, rejects cross-site Fetch Metadata, validates
JSON/form content type, duplicate fields, bounded body and strict DTO input.
No configured origin means denied POST. Behind a proxy, trusted hosting must
securely supply configured Host and existing Bearer headers. Ordinary navigation
and forms do not automatically carry Bearer headers. No new cookie/session login,
IdP or deployment is implemented. These checks supplement exact confirmation;
they are not a universal CSRF guarantee for arbitrary hosting configurations.

### Conflict, audit and safety

Transitioned requests and changed digest/snapshot return 409 without rebasing.
Committed retry is an explicit conflict here. Authentication denial is 401,
permission/confirmation denial 403, missing request 404, unsupported method 405,
unsupported content type 415 and invalid input 422. Storage/integrity failure uses
existing safe 503 mapping. Unknown commit outcome retains existing 503
reconciliation-before-retry semantics. Error feedback is not proof of rollback.
No traceback, SQL or credential is rendered.

Display strings/form attributes are escaped. Raw Tool/Evidence input and credentials
are omitted. Credential-like human reason text is rejected with existing basic
marker conventions; arbitrary unmarked sensitive prose cannot be universally detected.
Only governance pages allow same-origin forms through CSP. Overview/Incident Detail
retain no-form CSP. No scripts or dependencies are added.

Successful decisions write existing governance records, confirmation receipts and
audit events only. No UI audit table, Incident state application, checkpoint change,
Tool/Response execution, inference, LLM, improvement registry change, Promotion or
Rollback is performed. Full domain validation runs at commit in the existing service;
inbox refresh does not restore all authority or run expensive evaluation.

Limitations: two actionable domains, external trusted confirmation/hosting composition
required, no complete durable cross-domain queue, no pagination or browser automation.
Phase 8-4 monitoring remains read-only. Improvement Review/Promotion/Rollback UX
remains outside this phase.

```bash
uv run --offline pytest -q tests/integration/api/test_governance_dashboard.py
```

## Security AI monitoring (Phase 8-4)

`GET /dashboard/security-ai` and `GET /api/dashboard/security-ai` expose the same
immutable `SecurityAIMonitorView`. The Overview sidebar and Security AI section link
to monitoring; linked incidents lead to Incident Detail. Manual refresh reads durable
state only. Existing Bearer authentication and trusted header-forwarding hosting
remain required; ordinary browser navigation does not automatically carry Bearer
headers. No new authentication, dependencies, model operation or mutation UI is added.

Aggregate access uses the existing `GET:dashboard` policy. Every checkpoint is filtered
with Incident, workflow, artifact and Incident Detail access policies **before** its
payload is decoded. Denied incidents contribute neither IDs nor aggregate counts.
The application query uses one read transaction with SQLite query-only mode, through
the existing persistence boundary. Presentation never opens the database.

### Model signals and their meaning

Network XGBoost, Network IsolationForest and Authentication IsolationForest have
separate cards. Adapter labels identify the supported contract, not a recorded
adapter invocation. `AVAILABLE` means a contribution is retained, not live process
health. Explicit `not_run`, `failed` or `insufficient_input` coverage is displayed as
`NOT AVAILABLE`, with the original reported coverage shown separately. Unreported
models remain `UNKNOWN`. No model is diagnosed as broken from absent metadata.

Model-derived signals are investigation context, not Evidence.

Classifier labels and stored class probabilities are displayed as **MODEL CLASS
PROBABILITY**. They are not incident probabilities, attack certainty or SOC confidence.
No probability is reconstructed from labels. IsolationForest shows retained
`score_samples`, negative `score_samples`, decision function, empirical anomaly rank,
normalization threshold/decision and the selected operating point. Higher empirical
rank and negative `score_samples` mean more anomalous relative to the stored benign
reference; the raw score has the opposite direction. These values are not a verdict
that a host/account is compromised. No good/bad color gradient is generated.

An anomaly score is not an attack probability.

Fusion combines available model-derived signals for investigation context. Its
contributions, missing model kinds, agreement, coverage, limitations and confidence
are displayed separately. Its current confidence contract is `UNKNOWN`. Cross-domain
identity mapping remains `unverified` or `not_applicable` as retained.

Fusion agreement is not statistical confidence.

The conceptual lifecycle places investigation between model context and separate
Evidence/analysis, then advisory assessment, decision and Human Governance. It is not
an inferred causal graph. Actual lineage uses stored signal/result IDs, contribution
IDs, run ID, snapshot/checkpoint revisions, Fusion ID and assessment ID. Evidence
references are application source assertions, not proof of feature extraction. The
view does not create Evidence or make authoritative Incident severity decisions.

### Metadata, integrity and timestamps

Only retained package manifests supply explicit model name/version, schema/extractor,
ordered feature names, manifest SHA256 and fixed artifact-file SHA256 metadata. The
view does not scan model directories, read ML reports, run package loaders or infer
versions from filenames/git. A card summarizes the latest retained source result for
that model contract; it is not an inventory of presently loaded models.

Stored checkpoint canonical content/digest, Incident snapshots, assessment/Fusion
references, manifest metadata digests and local signal/contribution bindings are
checked. A narrow typed reader avoids full checkpoint decoding, whose analytical
validation rebuilds Fusion aggregation. It does **not** recompute Fusion or revalidate
its analytical conclusions on refresh. Existing domain validation remains unchanged.
Storage/reference mismatch fails closed through the existing safe storage-error path.
Metadata hashes are not proof of model security, current model-file validation or
publisher authenticity; artifact-file integrity status remains `UNKNOWN` because a
successful loader check is not durably retained.

Latest signal time is the stored source-result timestamp. Fusion's timestamp is its
source-observation watermark, not an execution clock. Missing timestamps remain absent.
The page lists **Latest Retained Signals** across authorized checkpoints, not a complete
historical signal log. There are no trend charts, synthetic points, offline F1/AUC,
health/uptime, latency or invented runtime metrics. Ordering is deterministic by actual
source time and explicit IDs; equal timestamps use stable identity tie-breaks.

Missing model data is preserved as UNKNOWN or NOT AVAILABLE.

No durable value is available for unknown fields. Empty model/retained-context states
remain visible without demo data. Raw feature values, event payloads, profiles/scalers,
training configuration, credentials, arbitrary source names and source-record strings
are omitted. Safe source type/count and opaque artifact references remain. All rendered
model labels, metadata and provenance strings are HTML escaped; existing no-form CSP,
no-store, nosniff and no-referrer headers apply.

The monitoring view does not execute model inference.

GET does not recompute Fusion, call an LLM, change Incident/checkpoint/Evidence state,
create review/approval records, consume confirmation or mutate improvement versions.
Model reload/retrain/threshold changes and promotion are outside this observation surface.
Limitations: retained checkpoint context only, no independent model health inventory,
no full historical telemetry or pagination, and existing Bearer hosting integration.
Self-improvement/version-management UI remains Phase 8-5 scope.

```bash
uv run --offline pytest -q tests/integration/api/test_security_ai_monitor.py
```
