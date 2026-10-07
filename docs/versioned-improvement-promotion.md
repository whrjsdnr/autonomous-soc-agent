# Human-governed versioned improvement promotion

Measured improvement does not authorize promotion.
Human Improvement Review approval does not itself authorize promotion.
Promotion requires a separate trusted identity, permission, and request-specific durable confirmation.
Rollback creates a new governance fact and does not rewrite history.
Promotion does not execute arbitrary candidate text.
Only explicitly supported typed artifacts may become active.
An active artifact affects runtime only through the typed InvestigationStrategyProvider boundary.
Code self-modification is outside Phase 7.
PROMOTABLE is not PROMOTED.

## Supported artifact and evidence

The only family is `INVESTIGATION_STRATEGY_DEFAULT`; it is not keyed by an incident.
The only supported Candidate type is `INVESTIGATION_STRATEGY`, operation
`REQUIRE_READ_ONLY_PERMISSION_COVERAGE`. The payload is the immutable typed
`InvestigationStrategy`, with a canonical nonempty tuple of `SYSTEM_READ`,
`NETWORK_READ`, and/or `FILE_READ`. WRITE, arbitrary strings, arbitrary JSON,
PROMPT, RULE, TOOL_SELECTION_STRATEGY, REVIEW and executable prose are unsupported.

Each immutable artifact pins the complete ReviewRequestContent and exact human
ReviewRecord ID/digest: Candidate, Dataset version/manifest, patterns and sample
provenance, Specification, TestPlan, Split, Variant, FrozenBaseline, both executed
results and Comparison. Creation time is metadata outside the content identity.
Integrity validation walks those exact durable sources, including consumed review
confirmation. New datasets or evaluations never rebind old requests or versions.

`PromotionEligibilityService` remains a read-only check. Request creation and
activation revalidate PROMOTABLE within their own transaction. Required acceptance
and safety must PASS and the exact trusted human review must APPROVE. Missing or
PARTIAL adjudication remains NOT_MEASURABLE/UNKNOWN; it is never zero-filled.
Source corruption raises an integrity error rather than becoming an eligibility
exclusion. Offline probes establish their bounded gate behavior, not production
LLM quality or exhaustive real-world safety. Review revocation is not implemented;
existing terminal reviews remain immutable.

## Version registry and baseline

`ImprovementPromotionStore` exposes requests and queries, not a public `set_active`
or arbitrary registration API. The activation service registers supported versions
only after separately confirmed authorization. Versions are monotonically assigned
integers; the Candidate and LLM cannot choose them. Artifact IDs hash their version,
typed payload and exact source snapshot. Queries return versions in version order.

A unique family/payload digest prevents duplicate strategy histories. An identical
registered payload raises `NoChange` for a new request; returning to it requires
rollback. Exact committed requests return their existing durable records after
re-authentication of the same provider/subject/session, without consuming another
confirmation. A stale uncommitted request never automatically rebases.

Initial active state is NONE with pointer revision zero. The existing production
behavior has no strategy constraint and cannot honestly be represented by the
nonempty coverage contract. No fake SYSTEM_BASELINE, Candidate, Review or Promotion
is created. First governed promotion becomes version 1. Rollback to initial NONE
is not supported; rollback targets must be registered versions.

## Independent human authorization and atomicity

`PROMOTE_IMPROVEMENT_ARTIFACT` and `ROLLBACK_IMPROVEMENT_ARTIFACT` are separate
permissions, granted only to ADMIN by the existing trusted role provider. Review
permission alone is insufficient. Request bodies contain no role claims.

Confirmation purposes are `improvement_artifact_promotion` and
`improvement_artifact_rollback`; identity, session, exact request content digest,
freshness and expiry are checked by the existing ProviderHumanAuthority and
SQLiteConfirmationConsumer. Review, promotion and rollback confirmations cannot
substitute for one another. Receipts contain no raw credential.

The existing identity context retains its legacy UUID scope field. Activation
uses a fixed family resource UUID, not a fabricated Incident. The v13→v14 migration
preserves all confirmation receipts and replaces the Incident-only FK with INSERT/
UPDATE scope triggers and incident delete/key-update guards: existing incident
receipts cannot be orphaned, and the family scope
is permitted only for the two activation purposes. Other orphan scopes are denied.
Authentication/RBAC/confirmation checks remain required; storage is not authority.

Promotion uses one `BEGIN IMMEDIATE` transaction: validate durable request and
approved sources, authenticate/authorize, reject stale expected pointer, consume
confirmation, insert immutable artifact/version, CAS pointer and insert immutable
PromotionRecord, then commit. Rollback validates the registered target and executes
the same confirmed CAS/audit transaction without creating a new version. Exceptions
roll back consumption, registration, pointer and audit together. Unknown commit
acknowledgement raises CommitOutcomeUnknown; it is never reported as success.
Reconcile through exact durable queries/retry before any further action.

## CAS, rollback and restart

Requests pin expected active artifact, version and pointer revision. Each committed
activation increments revision by one. Concurrent promotion/promotion,
promotion/rollback and rollback/rollback with the same expected pointer permit one
commit; stale competitors fail without automatic rebase. SQLite constraints and
explicit CAS protect history and prevent lost updates.

Rollback targets must be existing, same-family, integrity-valid supported artifacts.
Rollback adds a new RollbackRecord containing from/to pointers, request and trusted
permission/confirmation provenance. It deletes no version, PromotionRecord,
Candidate, Comparison or Review. Restart retains all versions, active pointer,
revision, requests, records and consumed confirmations.

## Runtime composition

Explicitly inject `RegistryBackedInvestigationStrategyProvider(store)` into
`InvestigationPlanner(strategy_provider=...)`. Each planning call reads and validates
the active typed artifact and its committed source/audit graph. NONE alone allows
existing unconstrained baseline behavior. Missing/corrupt active pointers, unsupported
payloads or bad sources fail closed; there is no silent fallback.

The planner continues to generate one LLM plan and apply existing registered-tool,
input and reference validation before strategy coverage validation. The strategy
constrains the plan; it does not fabricate tools, inputs, approvals or retries.
A subsequent planning call observes promotion or rollback. Plans already generated
are not retroactively rewritten. Policy and human execution governance remain
separate. Promotion and rollback invoke no Tool, Executor or Response action and
make no protected IncidentState mutation.

There is no automatic provider installation, Dashboard or application API. The
trusted application composition must opt in to this provider. This is an actual
production planner boundary, not an offline adapter masquerading as runtime.

## Persistence and limits

Apply the existing explicit migration chain through v13, then
`migrate_improvement_promotion(database)` to v14. Six bounded tables store artifacts,
pointers, promotion/rollback requests and records. Older consumers explicitly
recognize v14; future schemas fail closed. Migration failure rolls back the additive
schema and confirmation-table rebuild, preserving prior records.

Canonical JSON validation reuses only a compiled schema adapter; input payloads and
source verification results are never cached. Canonical bytes and strict validation
remain unchanged. Full source revalidation is intentionally conservative and can be costly as version
history grows. No caching across transactions, version ranking, success probability,
code generation, source rewrite, live API, deployment or model training is added.
An approved synthetic test graph demonstrates the contract, not production approval.

Versioning/governance infrastructure is intentionally separated from SOC incident
state so bounded artifact types can be added without changing promotion authority
semantics. No Harness, Server, Fleet or deployment framework is introduced.
