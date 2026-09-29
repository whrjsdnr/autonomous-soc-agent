# Phase 4-6 — Human-Governed Response Promotion & Execution Bridge

## Purpose and non-goals

A proposed action is not an authorized action.
A promoted action is not an approved action.
A response review is not a tool approval.
Policy approval requirements cannot be overridden by response review.
Execution-time validation is required even after promotion.

This phase adds explicit human-reviewed promotion after Phase 4-5's advisory stop.
It reuses existing Tool Approval and GovernedExecutor contracts. There is no
background worker, automatic review/promotion/approval/execution, new production
response tool, model training, external SOC integration or state mutation.
Tests execute only mock tools; actual saved models are used for upstream inference.

## Architecture

```text
Advisory ResponsePlan / ActionProposal
  → explicit ResponseReviewIntent
  → trusted human confirmation → ResponseActionReview
  → explicit PromotionRequest
  → current state / Registry / input / Policy revalidation
  → PromotedAction (not executable, not approved)
  → explicit bridge conversion to existing execution.ActionProposal
  → explicit pending Tool Approval request, when policy requires
  → independent trusted human Tool Approval confirmation
  → explicit ExecutionBridge.execute
  → final revalidation → existing GovernedExecutor → registered Tool
```

PromotionService has no ApprovalManager or Executor dependency. ExecutionBridge
constructs one GovernedExecutor using the same Registry and Policy objects as the
promotion validator. Trusted composition should retain one bridge per runtime;
none is selected globally. Phase 4-5 remains advisory-only and its existing direct
Executor/Coordinator rejection tests remain unchanged.

## Domain contracts and identity

All new domain models are frozen Pydantic models with forbidden extra fields.
Nested models are revalidated at public trust boundaries. Constructing a model
with a plausible shape does not register it or grant authority.

| Model | Binding and meaning |
| --- | --- |
| ResponseReviewIntent | Unique intent ID, exact PromotionTarget, reviewer, disposition, reason and blocker responses |
| ResponseActionReview | Unique review ID, confirmed intent and recording time |
| PromotionTarget | Incident, plan ID, complete advisory proposal, exact proposal digest and full StateAnchor |
| PromotionRequest | Unique request ID, registered response review and identical target |
| PromotionContent | Exact request, current snapshot, current PolicyResult and `response-promotion:v1` |
| PromotedAction | SHA-256 content identity and creation time, distinct kind from executable ActionProposal |
| ToolApprovalIntent | Promoted ID and the existing exact pending ApprovalRequest for independent confirmation |
| ExecutionProvenance | Incident/plan/proposal/review/request/promotion/action/approval references, snapshot, outcome, time and error category |

The target's retained proposal includes canonical input, Tool metadata, schema
binding and planning-time PolicyResult. Canonical content digests reuse the review
identity utility. Promoted identity excludes its own creation clock; upstream
review/request identities remain part of its exact meaning. Re-promoting the same
request under the same policy returns the same recorded artifact. A different
review/request is a distinct promotion, even when the tool input is identical.

The bridge explicitly derives an executable UUID using UUID5 over a fixed
`soc-agent:response-promotion:` prefix and the promoted digest. Existing executable
models otherwise use generated UUIDs; this new deterministic mapping preserves
exact action identity for approval matching and replay detection. PromotedAction
itself is not accepted by the existing execution or Approval model.

## Human response review and authentication

Review dispositions are `ready_for_promotion`, `reject`, and `request_changes`.
Only a registered, explicitly confirmed ready review can create a promotion
request. Incident Human Review and State Change Authorization are different
contracts and cannot substitute for it.

For readiness, every Phase 4-5 blocking reason requires an explicit BlockerResponse
with `addressed_for_promotion` plus an explanatory response. Any `unresolved`
condition prevents readiness. This is a human attestation of consideration for
promotion, not verified Evidence or proof of attack success. Policy denial and
Tool Approval requirements remain independently enforced regardless of the human
response. New Evidence or state changes require new planning/review because the
old snapshot becomes stale; this service never rewrites the proposal.

The existing HumanAuthority contract is reused with two additive, distinct
HumanAction purposes: `review_response_action` and `approve_promoted_tool`.
Confirmations bind the complete intent digest. Verified subject must match the
response reviewer. An arbitrary username or a token for another purpose fails.
Both service and bridge default to DenyHumanAuthority.

A production authentication provider is **not connected**. Tests use an explicit
test-only HumanConfirmations adapter. Real providers must authenticate a human,
enforce resource/action permissions, verify exact request intent, and prevent
confirmation replay. The Phase 4-4 ProviderHumanAuthority remains an opt-in
adapter; trusted context resolution and permission checking must resolve the
complete response/tool intent by digest, not rely on caller-supplied role claims.
No new provider credentials or production identity guarantees are introduced.

## Current-state, Registry and exact input revalidation

Promotion and execution read the authoritative SQLite store. CLOSED incidents
are rejected. Repository ID, incident, revision and full-state fingerprint must
match the reviewed snapshot. Thus Evidence additions and severity/status changes
invalidate an earlier promotion. Existing Decision/Evidence/Fusion validation and
registered Incident Review provenance are reused. AISignal/FusionResult do not
become Evidence, and model confidence is not converted into authority.

The current Registry is queried again. Missing tools, changed name/description,
permission/risk metadata or input JSON schema fail closed. Metadata/schema binding
does not attest the handler's code or its real operational behavior; there is no
implementation digest/capability-version contract in the existing ToolMetadata.

The exact canonical proposed input is validated with the current input model,
`extra="forbid"`, serialized with aliases/defaults/round-trip handling and validated
again. The serialized canonical value must equal the reviewed input exactly.
Phase 4-5 follows each Pydantic schema's coercion policy during planning; promotion
refuses normalization that would change that already reviewed value. Tests cover
runtime validators changing while JSON schema stays equal, including silent
correction and invalid input. No automatic input repair occurs.

## Policy re-evaluation

The injected current PolicyEngine is evaluated at promotion and before execution.
Current DENY blocks promotion/execution. Current REQUIRE_APPROVAL is retained and
requires separate exact Tool Approval. Read-only permission is not presumed safe:
high-risk reads still require approval, and destructive risk remains denied.
The existing default PolicyEngine acts as a minimum restriction: an injected
policy cannot turn its REQUIRE_APPROVAL into ALLOW or bypass its DENY.

Planning-time and promotion-time results are retained separately. A stricter
current result can be reflected in a new promotion. After promotion, any result
change, including its reason, invalidates that artifact; no automatic re-promotion
occurs. GovernedExecutor also evaluates current Policy immediately before calling
the Tool wrapper. No existing Policy implementation is weakened or modified.

## Existing Tool Approval bridge

`executable_action(promoted)` is the explicit conversion boundary. It validates
the registered promotion and current context, then creates the existing
`execution.ActionProposal` with exact incident, tool, canonical input and stable
action UUID. It does not approve or execute anything.

`request_approval(promoted, reason=...)` explicitly creates a **PENDING** request
through the existing Executor/ApprovalManager. Planning and promotion never call
this method. It only works where current Policy requires approval.

`approval_intent(...)` returns the exact pending request plus promoted ID for
independent human confirmation. `approve_tool(..., credential=...)` verifies this
confirmation, rereads the current context and unchanged request, then explicitly
invokes the existing ApprovalManager.approve. Response review is not reused.

Existing ApprovalManager authenticates no one itself: its `actor` is attribution
and trusted caller responsibility. The bridge therefore remembers which exact
approvals it independently confirmed and linked to which promotion. Calling
ApprovalManager.approve with a plain actor string does not make an approval
acceptable to this bridge. Existing legacy callers remain unchanged; the bridge
does not claim to retrofit authentication to every legacy application path.

## Explicit execution, replay and TOCTOU

`execute(promoted, approval_id=...)` is the only bridge method that invokes the
Executor, and only on an explicit call. It checks registered promotion, current
state, tool/schema/input and current Policy, then exact approval ownership,
incident/action/input/permission/risk binding and independently confirmed approval
content. State authorization objects or IDs and another promotion's approval
are rejected. The existing Executor then enforces policy and approval again.

The existing Executor reserves an action ID before awaiting the Tool wrapper.
Repeated or concurrently submitted attempts using that same executor are rejected,
including retries after tool failure/cancellation. Tests verify one successful
WRITE execution and rejection of a second execution using the same approval.
The manager does not persist a consumed flag; this is executor attempt tracking,
not a durable single-use approval ledger. Bridge approval links also belong to
one instance and are not restored into another instance.

These guarantees apply to the retained service/bridge/Executor in one process
and event-loop execution path. Cross-thread execution sharing is not promised.
There is no restart-safe replay protection, distributed coordination or multi-host
execution lease. Reconstructing runtime components is not a recovery protocol.

Final validation detects changes made after promotion/approval and before that
validation. **It is not an atomic transaction spanning SQLite and an external
Tool.** Another process/thread can change state after the last check, or conditions
can change while an async Tool runs. No lock, reservation, distributed fencing or
rollback of external effects is provided. Callers who bypass ExecutionBridge and
send its exported executable action directly to an Executor lose its state
revalidation. Those low-level APIs remain trusted application APIs, not a sandbox.
Future operational execution must address these remaining races explicitly.

## Persistence and audit/provenance

Promotion reviews, requests, promotions, approval links and execution events are
in-memory artifacts. Source advisory plans are also in memory. Recovering only a
promotion without its validated source/issuance graph would be unsafe, so no
SQLite tables or migrations were added. Phase 4-4 persistence remains unchanged.
There is no restart recovery for response execution provenance.

`PromotionService.reviews()`, `requests()` and `promoted_actions()` expose immutable
snapshots. `ExecutionBridge.audit_events()` returns immutable events linked to
those records and existing Tool Approval/action identities. Outcomes distinguish
`started`, `succeeded`, `rejected`, `failed`, and `outcome_unknown`. `started` means
dispatch was attempted, not proof that the handler ran. Pre-dispatch validation
failures are rejected; malformed artifacts can fail before sufficient provenance
exists to record an event. Exceptions/cancellation during dispatch are recorded
without logging credentials or full exception payloads. Cancellation is marked
unknown; a reported Tool failure does not prove absence of partial external effects.

These records are neither durable nor tamper-proof. Process death or failure to
append an in-memory event can lose provenance; a successful external effect cannot
be rolled back by an audit error. Production audit storage and recovery must be
designed before operational response deployment. There is no automatic retry,
replan, re-review, reapproval or rollback after any failure.

## Failure semantics

| Failure | Reported contract |
| --- | --- |
| Unknown/forged plan, review, request or promotion | InvalidPromotionArtifact or strict model validation error |
| Human confirmation missing/wrong purpose/subject | HumanAuthorizationDenied |
| Human rejects / requests changes | ResponseReviewRejected / ResponseChangesRequested |
| Current state differs / CLOSED | StaleSnapshotError / IncidentClosed |
| Tool absent / metadata changed / schema changed | PromotionToolMissing / ToolMetadataChanged / InputSchemaChanged |
| Exact input no longer validates | PromotionInputInvalid |
| Current policy denies / policy changed after promotion | PromotionPolicyDenied / PromotionPolicyChanged |
| Approval missing, pending or not independently confirmed | ApprovalRequiredError |
| Unlinked, substituted or cross-authorization approval | ApprovalBindingError |
| Underlying manager/executor rejection | Existing ApprovalError / ExecutionError subclasses |
| Action already attempted | ActionAlreadyAttemptedError |
| Tool failure / cancellation | Original Tool exception / cancellation propagated, with event |

No failure produces a successful partial promotion or an automatic retry. Model
shape/digest validity never replaces issuance provenance or human authentication.

## Validation and next phase

Tests cover immutable bindings, forged artifacts, exact input/schema validation,
current Policy restrictions, default denial, wrong-purpose confirmations,
approval substitution/replay, cross-incident/proposal reuse, state authorization
confusion and no automatic promotion-side approval/execution. Execution-time tests
change Evidence, severity/status/CLOSED, tool metadata/schema, policy and approval
binding after promotion or approval, and assert rejection before a Tool call.

Nine synthetic integration scenarios use real saved Security AI packages and
feature extraction, Mock LLM assessment, test-only human confirmation and mock
READ/WRITE tools. Model outputs are preserved. No production destructive tool,
external service integration or production authentication is exercised.

Next phase: design durable source-plan/review/approval/execution lineage together,
crash/outcome reconciliation, process-wide or distributed execution reservations,
trusted operational authentication/permission adapters, handler version binding,
side-effect verification and durable audit. These are not implemented guarantees.

## Verified results (2026-09-29)

- Promotion unit tests: **67 passed**, exit 0 (includes 19 security tests).
- Phase 4-5 advisory regression: **57 passed**, exit 0 (48 unit + 9 scenarios).
- Saved-model promotion scenarios and security tests: **28 passed**, exit 0
  (9 integration scenarios + 19 security tests).
- Full regression: **1,673 passed in 327.78s**, exit **0**, compared with the
  Phase 4-5 baseline of 1,597. The increase is 67 promotion unit tests and 9
  promotion scenarios; security tests are not counted twice.
- Ruff check, Ruff format check and `git diff --check`: exit 0.

Full execution output: `/tmp/soc-phase46-full.log`; separately recorded exit code:
`/tmp/soc-phase46-full.exit`. Temporary logs are local verification artifacts,
not durable audit records.
