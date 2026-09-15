# Phase 2-5: Governed response planning

`ThreatAssessment` is advisory input, never execution authority. `ResponsePlanner`
uses the existing structured LLM boundary to produce a proposal. Only the existing
`GovernedExecutor` invokes tools, after current policy and exact approval checks.
No production response adapters or dependencies are added.

## Proposal boundary

- `ResponsePlanDraft` and `ResponseStepDraft` contain only goal, tool name, input,
  and purpose. Extra fields, including authority and application IDs, are rejected.
- The application generates plan, step, and action UUIDs, UTC timestamps, and
  initial PENDING status. Domain plans use frozen models, tuples, and canonical
  JSON strings for nested tool inputs.
- Plans reference both `incident_id` and `assessment_id`. Before calling the LLM,
  the planner revalidates incident membership and every assessment evidence,
  observation, and hypothesis reference using `AssessmentResult`.
- The tool catalog is a snapshot of the injected registry, including trusted
  metadata and input schemas. Drafts must select from that snapshot. A registered
  destructive tool can be proposed; only policy determines its execution outcome.
- Tool schemas validate input before plan creation. Defaults and aliases are
  serialized before approval, using `ActionProposal.canonical_input`. The actual
  tool boundary validates again during governed execution.
- Plans contain 1–5 steps, fewer than investigation's eight, to bound side effects.
  This bounds the chain length, not its aggregate risk.

## Context and sensitive data

The prompt includes incident status/severity, the advisory assessment, its referenced
observations and hypotheses, and their supporting evidence summaries. Evidence
projection contains ID, source, tool name, and summary; raw evidence is excluded.
Unrelated evidence is omitted. All source content is JSON data, with explicit system
instructions against following embedded commands. Prompts guide least disruptive,
scoped, reversible actions; they do not enforce authorization.

The complete serialized user context, including the tool catalog, is limited to
64,000 characters, consistent with assessment. Oversized context raises an error
before any LLM call; no silent truncation or reference removal occurs. This is a
character bound, not a token estimate. Summaries can still contain sensitive data;
this is not a redaction engine.

## Execution and human approval

```python
plan = await planner.create_plan(incident_state=state, threat_assessment=assessment)
step_id = plan.steps[0].step_id
result = await coordinator.execute_step(incident_state=state, plan=plan, step_id=step_id)
# When the returned step is blocked by an approval requirement:
action = coordinator.prepare_step(incident_state=state, plan=result.plan, step_id=step_id)
request = executor.request_approval(action, reason="Review this exact scoped action")
# Only a trusted human-facing caller records this decision:
approvals.approve(request.approval_id, actor="human-operator")
result = await coordinator.execute_step(
    incident_state=state,
    plan=result.plan,
    step_id=step_id,
    approval_id=request.approval_id,
)
```

The coordinator only depends on the executor. It neither creates nor approves
requests. `prepare_step` preserves the step action UUID and canonical inputs,
including across BLOCKED snapshots. Approval binds incident, action UUID, tool,
canonical input, permission, and risk. Another action with identical input is still
another action. The executor checks policy DENY before consulting approval; even
an approved exact record cannot override it.

`execute_plan` awaits steps sequentially and stops on the first block or failure.
Existing blocked steps require explicit `execute_step` after human intervention.
Completed and failed steps cannot be explicitly retried. There is no automatic
retry or parallel execution: a failed or interrupted action may already have side
effects. Callers must serialize response submissions; this helper is not a global
scheduler. The shared executor prevents repeated attempts of the same action in
one runtime, including submissions using stale plan snapshots.

## Outcome semantics and limits

- Execution/approval errors become BLOCKED with their original error type and reason.
- Tool boundary errors become FAILED, consistent with investigation. These include
  input/lookup errors before handler invocation as well as runtime/output failures;
  the retained error type distinguishes them. FAILED does not imply a side effect.
- COMPLETED means the tool boundary returned successfully. It does not prove that
  an attack stopped, containment worked, or the incident can be closed.
- Incident state, severity, confidence, observations, and hypotheses are unchanged.
  The coordinator returns a new plan snapshot and the unchanged incident.
- Cancellation propagates. There is no durable recovery, result archive, or new
  audit infrastructure. Tool results are not retained as mitigation evidence.
- Approval actor authentication remains the trusted caller's responsibility.
  IDs and frozen models are application integrity mechanisms, not cryptographic
  authorization. Trusted Python code must not use validation-bypassing constructors
  for untrusted data.

Next, a separate Verification phase should collect independent post-action evidence,
check scoped expected effects and unintended impact, distinguish failed/unknown
outcomes, and preserve action-to-verification provenance. Incident closure needs
an explicit validated lifecycle decision after that verification. Rollback,
persistence, reflection, learning, and self-modification remain deferred.
