# Phase 4-3: Human review and governed decision application

## Purpose and existing contracts

This phase adds explicit human review and application of authorized incident
metadata changes. It does not create decisions automatically, infer attacks, plan
responses or execute tools. It has no UI, authentication server or durable database.

The inspected `IncidentState` is frozen, including nested records and tuples.
Its append methods return new validated snapshots; it has neither a version field
nor a status-transition API. Existing statuses are NEW, TRIAGING, INVESTIGATING,
ASSESSING and CLOSED; there is no OPEN value. Severity is INFO/LOW/MEDIUM/HIGH/CRITICAL.
Investigation has its own step lifecycle, which is not an incident lifecycle policy.

`IncidentDecision` remains advisory. Its identity excludes creation clocks, and it
retains assessment, Evidence references, interpretations and a separate original
FusionResult. Review registration reuses `AssessmentResult` and
`validate_assessment_fusion` reference/lineage checks, plus checks that the retained
interpretations match the supplied state. It does not invoke the DecisionEngine,
LLM, inference, feature extraction or `fuse`. Shared retained-Fusion reconstruction
is integrity validation, not a new interpretation or new model execution.

Existing `ApprovalRequest` binds Tool metadata, action identity and canonical input.
ApprovalManager's actor string is attribution, not authentication. GovernedExecutor
rechecks policy and exact action binding; none of those contracts are changed or
reused as incident-state authorization. Existing PolicyEngine controls tool risk
and permissions; the new transition rules have a separate purpose and version.

## Contracts and explicit APIs

The `soc_agent.review` package provides immutable Pydantic contracts with forbidden
extra fields. Identity/reference information is nested rather than duplicated:

| Contract | Meaning |
| --- | --- |
| `StateAnchor` | Repository instance ID, incident ID, revision and full-state SHA-256 |
| `ReviewTarget` | Incident, Decision ID, complete Decision content digest, Decision/rule versions and anchor |
| `HumanReviewRequest` | Explicit submission of an existing Decision and state for review |
| `ReviewIntent` | Exact reviewer, outcome and reason requiring human confirmation |
| `HumanReviewRecord` | Recorded human review with identity, request reference and timestamp |
| `StateChangeRequest` | Review/target, unique status/severity changes with before/after values, reason and transition version |
| `StateChangeAuthorization` | Separate kind, identity, complete request, request digest, verified authorizer and issuance time |
| `ApplicationResult` | New state and successful immutable application audit |
| `ApplicationFailure` | Failed attempt context/reason with no new or partially updated state |

Review outcomes are distinct, not a permission boolean:

- `acknowledged_without_authorization`: reviewed without authorizing a change.
- `additional_investigation_requested`: exposes the corresponding request property;
  it does not schedule or execute an investigation.
- `state_change_rejected`: disallows a change proposal from that review.
- `state_change_may_be_proposed`: allows creating a separate proposal, **not applying it**.

One review request can have one final record. Another review requires an explicit
new request. A request has at most one authorization; no hidden replacement,
auto-approval, revocation or expiry mechanism is supplied.

The caller uses `HumanReviewService` explicitly:

1. `request_review(state, decision)` validates and registers the existing analysis.
2. `record_review(request, reviewer_id=..., outcome=..., reason=..., credential=...)`
   requires external confirmation of exactly that intent.
3. `propose_change(review, changes=..., reason=...)` permits only eligible reviews.
4. `authorize_change(request, review, credential=...)` requires a separate human
   confirmation for the complete request digest and state-change permission.
5. `apply(state, decision, review, request, authorization)` verifies the full chain
   and asks the authoritative store to commit atomically.

Creating any of the first four records never updates incident metadata. Models
constructed outside the service, or objects altered through `model_copy` or
`model_construct`, do not acquire issuance provenance. Boundary round trips
revalidate nested values, and the service requires exact registered records.
Unknown references and altered records fail closed.

Only status and severity may be requested, at most once each. Their discriminated
models use the existing enums; empty, duplicate and no-op changes are rejected.
Changes are canonically ordered by field. There is no arbitrary patch dictionary.
Evidence, Observation, Hypothesis, confidence, timestamps, policy, tool approval
and registries are not requestable fields. The service alone advances updated_at
as commit metadata while preserving all other unrequested fields.

## Human authentication and authorization trust boundary

No authenticated user-principal infrastructure exists in the inspected project.
`HumanAuthority` is therefore an explicitly injected trusted boundary. Its `verify`
method must verify **authenticated human identity, permission and explicit intent
for the exact action and binding digest**, not merely that a user is logged in.
Review and authorization have different purpose tags. It returns a validated
`VerifiedHumanAction`; the service checks purpose and binding, and for reviews also
checks the explicitly supplied reviewer ID against the verified subject.

The default `DenyHumanAuthority` rejects every attempt. An arbitrary reviewer ID,
LLM text, Decision, AISignal or FusionResult cannot issue an authorization.
Production composition must install an adapter backed by real authentication and
human confirmation, including credential freshness and replay checks. No production
adapter or login/role-management service is implemented here. The test-only
`HumanConfirmations` fixture models a trusted external channel with named human
roles and one-use confirmations bound to exact digests; it is **not authentication
for deployment** and is not exported by the application package.

The service retains issued authorizations in its own protected ledger and accepts
only exact issued objects at application. A copied/forged shape or recomputed hash
is insufficient. Issuance is not cryptographically portable: a different service
instance rejects another instance's ledger records. Review/request/authorization
identities are UUID references; content digests use existing strict canonical JSON.
Neither kind of identity proves source authenticity.

Authority implementations, the service, and the low-level store are trusted
composition infrastructure. They must not be injected by request payloads or
registered as LLM tools. The store's CAS callback is a trusted, pure application
builder, not a user-supplied function. Giving hostile code direct access to replace
these components or modify Python process memory is outside the security boundary.
Credentials are not stored in reviews, authorizations or application audit.

## Snapshot, TOCTOU and concurrency

`state_fingerprint` covers the **entire revalidated IncidentState**, including
Evidence contents, interpretations, confidence and all timestamps. Canonical JSON
sorts object keys; arrays preserve order. Even an array reorder conservatively
counts as another snapshot. Matching status/severity alone is never enough.

`InMemoryIncidentStateStore` adds a monotonically increasing per-incident revision
and a repository-instance UUID outside the original state model. The anchor binds
both content and repository/revision, preventing stale content, ABA-style revision
replays and reuse in a newly constructed store. Review also pins the complete
Decision digest, so changes to fields omitted by the Phase 4-2 semantic identity
(such as an assessment creation clock) still invalidate the binding.

These checks establish a review-to-application snapshot binding. They do not
retroactively prove that the original Assessment was generated from that state,
nor that Evidence/model execution was authentic.

The service checks state before and after external human confirmation. Application
uses `IncidentStateStore.compare_and_apply`: under one shared store lock it checks
anchor and unused authorization, builds and validates the new state and success
record, prepares a replacement store object, then swaps it once. State, consumed
authorization IDs and success audit change together. Other services using the same
store instance cannot both commit from the same revision. Threads using the same
authorization produce one success and one replay rejection; distinct authorizations
for the same snapshot produce one success and one stale rejection.

`append_evidence(anchor, evidence)` is a separate trusted ingestion CAS using the
existing append-only IncidentState API. It advances the same revision and
invalidates pending approvals, even when status and severity do not change.
The existing InvestigationOrchestrator is not automatically wired into this store;
a future composition layer must make it the authoritative store for **all** writes.
Detached state objects elsewhere in the process are not synchronized magically.

The protocol separates atomic storage responsibility from fingerprinting. A durable
adapter must provide cross-process atomic CAS and commit new state, consumption and
success audit in the same transaction, including uniqueness/serialization controls.
It must not report failure after a hidden successful commit. Such an adapter is not
implemented. A hash alone does not provide locking, durability or authentication.

## Explicit minimum transition policy

`incident-state-transition:v1` is a new documented incident metadata policy because
the previous repository had no incident transition policy. It permits:

```text
NEW -> TRIAGING -> INVESTIGATING -> ASSESSING -> CLOSED
                       ^               |
                       +---------------+
```

Sequential forward transitions require human authorization; ASSESSING may return
to INVESTIGATING when the human requests another investigation cycle through a
new eligible review/proposal. Skips and other backwards transitions are rejected.
CLOSED is terminal: both reopening and severity edits on a CLOSED incident are
denied in v1. Closure is an explicit administrative lifecycle change, not a claim
that compromise was absent or recovery was verified.

A non-CLOSED incident may receive any different valid severity, including a human
chosen decrease. There is no inferred severity mapping, score threshold or automatic
copy of Assessment severity. Exact before-values and all changed fields must match
the authorized request. A status/severity pair is one atomic request; it never
partially applies the valid half if another change fails.

## Audit, provenance and failures

Success records retain target Incident/Decision/full Decision digest and old anchor,
review ID, request ID, authorization ID, verified authorizer, exact field before/after
values, transition version, application identity/time and resulting anchor. The
service's immutable registries retain the referenced Decision, review request,
review record, state request and authorization. `reviews()`, `authorizations()` and
store `applications()` expose tuple snapshots rather than mutable collections.

`failures()` retains failed application attempts separately, with the registered
request when known, supplied authorization ID when structurally available, error
class and reason. This preserves the known chain and changes without accepting an
untrusted altered payload as the registered proposal. Unknown/malformed requests
have no invented registered reference. Failure records contain **no IncidentState**.
Schema and unexpected runtime errors use sanitized reasons rather than recording
raw inputs/credentials. The original exception is re-raised unchanged; no partial
ApplicationResult, normal fallback or automatic retry is returned.

Failed construction, validation or pre-commit storage operations leave authoritative
state, authorization consumption and success audit unchanged. An unconsumed
explicit authorization can be retried by a caller after a transient failure only
if the exact snapshot is still current. A successful authorization is never reusable.
The failure audit is in the service and is not atomically durable with a database.

Records are frozen and append-oriented within their component lifetimes, but there
is no durable audit log, signature, tamper-evident chain or administrator-resistant
storage. Process termination loses the store and issuance/review/failure ledgers.

## Governance boundaries and limitations

The package does not import or call Tool execution, response planning, approval
manager mutations, PolicyEngine evaluation or registry registration. Existing
Tool Approval cannot pass the exact StateChangeAuthorization boundary; conversely,
a state authorization ID does not exist in the Tool ApprovalManager and cannot
satisfy GovernedExecutor. Tool governance and packaging modules remain unchanged.

Decision generation, review completion, proposal creation, authorization issuance
and actual state application are separate operations. Fusion confidence stays
UNKNOWN and is not a new approval confidence. Model agreement never triggers
approval. Advisory concern is not promoted to verified compromise. Source Evidence,
observations, hypotheses and model context remain unchanged by application.

Implemented scope is domain contracts, an injected trusted human boundary with
default denial, and atomic/replay protection for a shared **single-process** store.
Not implemented: a production authentication/authorization provider, UI, durable
review/issuance/audit storage, cross-process concurrency, crash recovery,
authorization revocation/expiry or deployment integration. Do not present these as
provided guarantees. Tests are synthetic contract checks, not real SOC efficacy or
proof of secure external authentication.

## Validation and next phase handoff

Units cover review outcomes and missing identity, default denial and role/purpose/
binding checks, unknown references, immutable records, exact request binding,
forbidden fields/enums/no-ops, the complete status transition matrix, severity and
multi-field application, full snapshot changes, issuance races, different Decision
clocks, stale/replayed authorizations, concurrent distinct services, failures before
commit, failure audit, Tool Approval separation and forbidden governance calls.

Nine integration scenarios use synthetic SecurityRecords, actual feature extraction,
the pinned saved Phase 3-6 packages and their genuine AISignals, FusionEngine,
ThreatAssessor with **MockLLMClient**, and IncidentDecisionEngine. No model prediction
is edited or model retrained. Only the analytical LLM is mocked; human identity is
represented by the explicitly described test boundary and storage uses the real
in-memory CAS implementation. Scenarios cover review-only, investigation request,
approved severity/status, Evidence-added stale snapshots, cross-incident reuse,
replay, mixed approval types and injected pre-commit failure.

Next work should integrate an authenticated human confirmation adapter and, if
required, durable review/issuance records and a transactional state repository.
All write paths must share the authoritative repository. Do not enable state
application merely by replacing the default deny boundary with an allow-all adapter.
No response planning or Tool execution is included in this handoff.

## Verified results (2026-09-23)

- New units: **82 passed**; saved-package integration scenarios: **9 passed**.
- Final focused run: **91 passed in 2.40s**, exit code 0
  (`/tmp/soc-phase43-focused-final.log`).
- Full `uv run --offline pytest -v`: **1,479 passed in 300.92s**, exit code 0
  (`/tmp/soc-phase43-full-final.log`), compared with the Phase 4-2 baseline of 1,388.
- The first full invocation stopped during collection, exit code 2, because a new
  test basename matched an existing Fusion test module. Adding the review test
  package marker resolved that collision. No test or assertion was removed.
- Full Ruff and format checks passed. Git diff whitespace checks and explicit
  whitespace checks of all 17 new files passed.
- Existing untracked `tests/fusion_support.py` was preserved. Existing production
  modules, tests and dependencies were unchanged. No commit or push was performed.
- The full regression verifies the scoped domain/in-memory implementation. It does
  not validate a production authentication provider, durable state store or
  cross-process deployment; those capabilities remain unimplemented as listed above.
