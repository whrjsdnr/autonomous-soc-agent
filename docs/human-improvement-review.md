# Human-governed improvement review (Phase 7-4)

Improvement Review is separate from Tool Approval, Incident Review, and State Change Authorization.

Candidate → specification/test plan → offline variant/frozen baseline → paired results → comparison → review request → trusted human decision → immutable review record → **STOP**.

An APPROVE decision does not promote or apply a candidate.
Human Review authorizes only progression to promotion consideration.
Phase 7-5 must define a separate explicit promotion authorization. There is no runtime, API, or dashboard integration here.

## Evidence and eligibility

`soc-human-improvement-review:v1` binds every immutable source ID/content digest, dataset manifest, partition, frozen baseline, cases, metric definitions and safety invariants. Request creation and queries reuse full durable source replay validation through candidate, pattern, dataset, sample, Evaluation and Feedback provenance. Corruption, missing parents and foreign bindings raise integrity errors; they never become normal exclusions.

Requests may preserve a diagnostic NOT_REVIEWABLE state for unavailable evidence. Non-constructible variants, missing baseline, unexecuted comparison and absence of measurable paired results are typed blocking reasons. These requests cannot authorize progression. REJECT and DEFER can record a human disposition without changing sources.

Summary metrics, deltas, acceptance and separate baseline/candidate PASS/FAIL/UNKNOWN counts are convenience views of the pinned comparison. Limitations remain visible. No ranking, AI approval recommendation or success probability is produced.

Offline improvement does not imply production safety.
UNKNOWN safety evidence is not equivalent to PASS.

V1 APPROVE requires a reviewable request, every hard invariant PASS in **both** arms, and every acceptance criterion PASS. Any FAIL or UNKNOWN blocks APPROVE, independently of improved metrics. REJECT or DEFER remain possible; DEFER requests additional evidence and is not a failure verdict. The present coverage adapter does not exercise downstream Policy/Approval gates, so its UNKNOWN evidence cannot obtain APPROVE. Future evidence requires a new request, never editing an old summary.

## Trusted humans and confirmation

AI-generated candidates cannot self-approve.

Trusted authentication providers must return a fresh human principal. Trusted RBAC lookup grants `REVIEW_IMPROVEMENT_CANDIDATE` to APPROVER and ADMIN; ANALYST/RESPONDER permissions do not grant it. No request-body role/principal claim is accepted. Existing incident-scoped identity infrastructure uses a validated supporting incident for permission lookup; this remains an independent improvement domain and does not authorize changes to that incident.

The separate confirmation purpose is `improvement_review_decision`. Confirmation binds provider, human, session, expiry and the exact submission digest (which includes request ID/digest, decision, reason and note). The existing SQLite durable confirmation consumer runs in the **same transaction** as the record insertion. Other purposes cannot be reused. Credentials are never persisted. Human notes are limited to 1000 plain-text characters and reject the existing basic credential patterns; notes never become instructions or authority.

All three decisions are terminal. First committed decision wins, including DEFER; changing a disposition requires new evidence/request. A retry by the same principal/session with the exact submission returns the committed record without consuming another confirmation. Competing decisions cannot overwrite it. The unique request constraint and SQLite write transaction serialize independent processes. Consumed confirmations survive restart; transaction uncertainty follows existing fail-closed database behavior. Lock acquisition uses the existing configurable bounded SQLite timeout. A busy timeout propagates a storage failure without committing a review; the service introduces no automatic retry. Process race tests configure the supported 60-second timeout so full graph validation can finish while the competing process waits.

## Durable snapshots and boundaries

Explicit additive migration v12 → v13 creates `improvement_review_requests` and `improvement_review_records`; existing records are preserved. Logical request identity excludes its creation time, and canonical queries sort by ID. A terminal record pins the exact request/evaluation snapshot and authenticated verification receipt. Queries validate both source graph and consumed receipt. New candidates, datasets or comparisons never rebind an old request/record.

Offline query methods: `get_review_request`, `list_review_requests`, `get_review_record`, `get_review_record_for_request`, `list_review_records`.

Review services have no orchestrator, prompt registry, strategy registry, Policy mutation, executor, deployment or LLM dependency. APPROVE, REJECT and DEFER create only review records and consume the bound confirmation. Historical candidates and evidence are retained. Production behavior remains unchanged.
