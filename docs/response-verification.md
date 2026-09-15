# Phase 2-6: Response verification

## Execution success versus mitigation success

A response step marked COMPLETED means its tool boundary returned successfully.
It does not mean a threat was mitigated. For example, a firewall adapter can report
“rule successfully created” while independent authentication logs still show attacks.
That combination is response COMPLETED and verification outcome FAILED.

Verification is a separate boundary with three responsibilities:

1. `VerificationPlanner`: propose what to check, using a structured LLM draft.
2. `VerificationOrchestrator`: collect evidence through governed read-only tools.
3. `VerificationAssessor`: interpret those new records using a separate structured draft.

The planner never declares the outcome. The assessor has only an LLM dependency,
with no tools, executor, policy, approval, or incident mutation capability.

## Target and lifecycle

One completed `ResponseStep` is the verification unit. PENDING, EXECUTING, BLOCKED,
and FAILED responses are rejected before calling the planner LLM. A failed response
may have side effects, but assessing those requires a later recovery workflow.

```text
ThreatAssessment → ResponsePlan → human-approved governed response → COMPLETED
    → VerificationPlan → governed read-only checks → new Evidence
    → VerificationAssessment
```

The plan binds `incident_id`, `assessment_id`, `response_plan_id`, `response_step_id`,
and a frozen `target_action` snapshot. Its `target_action_id` property exposes the
response action UUID. Tool name, canonical input, purpose, and action identity must
still match the supplied completed response at collection and assessment time.
The assessment copies these provenance IDs and adds `verification_plan_id` and its
own application-generated `verification_id`.

Each verification step has a distinct, stable `verification_action_id`. It is never
regenerated during prepare/execute. The domain uses frozen Pydantic models, tuples,
UTC timestamps, unique step/action/evidence IDs, and canonical JSON input strings.
Existing `ActionProposal.canonical_input` remains the single canonicalization rule.

Drafts contain semantic content only. The application assigns IDs, state, timestamps,
and bindings. Each plan contains 1–5 checks. `expected_signal` describes a condition
to look for; it is not evidence and is never appended as an observation or hypothesis.

## Post-action evidence provenance

Planning snapshots all existing evidence IDs as `baseline_evidence_ids`. These can
never become the plan's verification evidence. A successful governed check produces
a fresh Evidence record through the existing investigation `evidence_from_result`
adapter, appended using `IncidentState.add_evidence`. The adapter's generic summary
still says “investigation result”; its complete raw result envelope is preserved.
There is no separate evidence subclass or verification flag.

Collection steps record `started_at` and their resulting `evidence_id`. The result
validates incident membership, tool name, source, collection and receipt timestamps,
and baseline exclusion. Evidence must have timestamps at or after that step's start,
and the step must start at or after plan creation. Duplicate evidence IDs are rejected.

The assessor can cite only this plan's completed collection evidence IDs, even if
other records exist in the incident. Unknown IDs, pre-action IDs, mixed valid/invalid
references, and records from other verification runs are rejected atomically. No
partial assessment or state mutation occurs on invalid analysis. With zero collected
evidence, `NoVerificationEvidenceError` is raised before any LLM call.

**Timing limit:** response steps have no execution timestamp or signed execution
receipt. Planning relies on the application's completed response snapshot. New
collection provenance establishes that reads happened in the verification lifecycle;
it does not prove that underlying log events occurred after the response. The reused
adapter's `observed_at` is receipt time. Real adapters must expose source event windows,
freshness, and query coverage; future execution receipts should provide an explicit
response completion time. Trusted Python callers must preserve returned snapshots
and must not forge models or bypass validation.

## Read-only capability and governance

The observation-only catalog accepts SYSTEM_READ, NETWORK_READ, or FILE_READ with
READ_ONLY or LOW risk. Writes and MEDIUM/HIGH/DESTRUCTIVE risks are excluded even if
policy might authorize them. This is a capability restriction, not another policy
engine: verification observes the environment and cannot remediate it.

Draft selection must belong to the catalog snapshot taken before the LLM call. Input
schemas are validated, defaults/aliases serialized, and canonical inputs revalidated.
The existing tool boundary validates again during execution.

`GovernedExecutor.execute` adds a backward-compatible `require_read_only=False`
keyword. Verification always passes True. The executor checks the actual selected
tool's capability before governance/execution, using the same `ToolMetadata`
capability predicate as the planner. This also protects against a different execution
registry containing a write tool under the same name, manually assembled plans, or
an approved record for a forbidden capability. Approval cannot widen this scope.
Existing response/investigation calls keep their prior default behavior.

Verification still passes policy on every execution. Keeping one tool execution path
preserves policy, replay protection, failure behavior, and the location for future
audit instrumentation. No new audit backend is introduced. Metadata and adapters are
trusted application setup; this is not a sandbox for malicious Python handlers.

## Collection failures and outcome semantics

| Result | Meaning |
| --- | --- |
| Step COMPLETED | A new evidence record was collected successfully |
| Step BLOCKED | Governance prevented collection |
| Step FAILED | Tool validation, runtime, output, or evidence conversion failed |
| Outcome VERIFIED | New evidence supports the intended scoped security effect |
| Outcome PARTIALLY_VERIFIED | Some intended effects are supported, others are not |
| Outcome FAILED | Collected evidence indicates mitigation did not occur |
| Outcome INCONCLUSIVE | Evidence is insufficient or ambiguous |

Failure details retain the originating error type and reason. Tool failure is not
mitigation failure. With some evidence and incomplete collection, assessment is
allowed: the prompt includes pending/blocked/failed checks as coverage gaps. Confidence
in [0,1] is independent of the outcome, including high confidence in INCONCLUSIVE.

`execute_plan` awaits steps sequentially and stops at the first block or failure.
Existing blocks require an explicit step call after the cause is addressed. Failed
or completed steps cannot be retried. A shared executor prevents stale snapshots from
replaying the same action ID in one runtime. Cancellation propagates and attempted IDs
remain reserved. Callers must serialize submissions; this is not a distributed scheduler.
A new explicit plan may recheck the same completed response with new IDs; no hidden
reverification loop exists.

## Context and prompt injection

The context separates prior incident/assessment information, the executed target,
expected effects, and post-action verification evidence. No response ToolResult is
supplied as proof. Prior raw evidence is excluded. Post-action normalized results are
included in full because truncation could remove contradictory findings. The complete
serialized user context is capped at 64,000 characters; excess context causes an error
before the LLM call instead of silent truncation. This is not token estimation or a
secret redaction engine; trusted adapters must minimize sensitive data in results.

Logs and all other source text remain JSON data, with instructions never to follow
embedded commands. Structured outputs forbid action recommendations and application
identity fields. Reference validation prevents invented evidence IDs from becoming
valid citations, but cannot prove semantic entailment or the truth of source data.
Mock tests validate the boundary and lifecycle, not real model judgment accuracy.

## Usage

Given a completed response plan, its matching assessment/state, and trusted shared
registry/executor setup:

```python
planner = VerificationPlanner(llm_client=planner_llm, registry=registry)
plan = await planner.create_plan(
    incident_state=state,
    threat_assessment=assessment,
    response_plan=completed_response,
    response_step_id=response_step_id,
)
collection = await VerificationOrchestrator(executor=executor).execute_plan(
    incident_state=state,
    response_plan=completed_response,
    plan=plan,
)
outcome = await VerificationAssessor(llm_client=assessor_llm).assess(
    incident_state=collection.incident_state,
    threat_assessment=assessment,
    response_plan=completed_response,
    plan=collection.plan,
)
```

The caller handles collection failure or no evidence explicitly. Assessor errors do
not remove evidence already collected. Neither outcome assessment nor collection
changes incident status/severity/confidence, creates observations/hypotheses, approves
actions, or modifies policy. Collection only appends evidence.

## Deferred and next decision boundary

VERIFIED does not close an incident: a single action's intended effect may cover only
part of the incident. FAILED does not trigger another response, rollback, or retry.
A later explicit Incident Outcome Decision should consider the original assessment,
all response action statuses, per-action verification outcomes, confidence, evidence
references, source timing/coverage, collection failures, residual threats, and remaining
uncertainty. Any new response must return through planning, policy, and human approval.

Durable execution receipts, persistence/history, distributed coordination, real SIEM/
firewall/IAM/EDR adapters, automatic closure, rollback, reflection, learning, and
self-improvement remain outside this phase.
