# Bounded autonomous investigation

Phase 2-12 composes existing boundaries into a finite investigation session.
The coordinator contains no security reasoning thresholds or model-selection
heuristics. `AdaptiveInvestigationPlanner` makes each new semantic decision;
registries and execution boundaries retain their authority.

## Lifecycle and API

```text
InvestigationContext
  → AdaptiveInvestigationPlanner
  → validated decision
      continue_with_tool → InvestigationOrchestrator → GovernedExecutor → Evidence
      continue_with_ai   → SecurityAIInvestigator → SecurityAIResult → AISignal
      ready / stop / escalate → return session
  → append execution history, advance budget
  → next adaptive decision (within the fixed bound)
```

`BoundedInvestigationCoordinator(planner=..., tool_orchestrator=...,
ai_investigator=...).run(context)` returns an immutable
`AutonomousInvestigationSession`. Supply the existing `InvestigationContext`
with an incident, optional initial signals and Tool/AI histories, and an
`InvestigationBudget`. Existing context validation still requires prior evidence,
signals, or history; this coordinator does not replace initial investigation.

The session contains `initial_context`, accumulated `context`, ordered `rounds`,
and `terminal_decision`. Each `AutonomousInvestigationRound` retains its complete
adaptive decision, generated plan, execution snapshot, new Evidence/Signal IDs,
and timestamps. UUID links trace session → round → decision → plan → execution
→ Evidence or source Result/Signal. Session validation checks these relationships
and reconstructs the accumulated context from the round records.

## Budget and terminal outcomes

One planner attempt consumes one round, including a terminal decision or a fatal
planning failure. Round numbers are one-based; budget `current_round` counts
consumed attempts. A caller-supplied nonzero current round is respected.
The coordinator uses a fixed `range(current_round, max_rounds)` established at
entry and rejects any planner change to incident or budget. It never increases
`max_rounds`.

After consuming the budget, it creates an `ESCALATE_TO_HUMAN` terminal decision
with reason `Investigation budget exhausted`. This synthetic decision adds no
round and makes no planner, LLM, Tool, or AI call. An already exhausted valid
context follows the same path immediately.

- `READY_FOR_ASSESSMENT`: stop investigation; the caller may invoke an assessor
  later. This is neither confirmation of a threat nor incident resolution.
- `STOP_INSUFFICIENT`: normal stop with insufficient information; no incident closure.
- `ESCALATE_TO_HUMAN`: analyst escalation recommendation; no approval request or
  automatic action approval.

## Evidence, signals, and history

Tool execution uses the existing orchestrator's returned IncidentState snapshot.
The coordinator verifies that previous Evidence remains intact, the new Evidence
matches execution references, and unrelated incident fields remain unchanged.
It does not insert Evidence itself. The next planner sees that updated state.

AI execution produces separate AISignals, never Evidence, observations, or
hypotheses. Signals accumulate in `session.context.signals`; AI execution history
retains Results and source provenance. Initial historical signals are normalized
using existing context validation. Newly appended signals must have unique
signal and source-result IDs, using the existing signal context validator.

Tool plans with execution statuses accumulate in `tool_history`; full AI execution
snapshots accumulate in `ai_history`. The existing adaptive projection supplies
status, capability, references, and error type to subsequent decisions without
raw inputs, raw results, or tracebacks. Histories retain canonical inputs for the
existing exact-repeat rejection. Same capability with different input remains
eligible for an explicit new decision.

An optional synchronous application-owned `ai_source_resolver(state, plan)`
returns `{selection_step_id: tuple[evidence_id, ...]}`. The AI investigator
validates these references before inference and uses `create_ai_signal` afterward.
Without a resolver, source references are empty. These are related Evidence
references, not proof that each model feature was extracted from an Evidence
field. The coordinator does not infer or fabricate that relationship.

## Governance and failure handling

Tool execution always calls `InvestigationOrchestrator.execute_plan` with
`require_read_only=True`. This additive option defaults to False for existing
orchestrator callers and forwards the existing GovernedExecutor read-only gate.
The current registered capability is checked at execution; Policy and Approval
checks remain in that executor. The coordinator supplies no approval IDs and
never approves an action. A blocked Tool attempt is recorded, not bypassed.

SecurityAIInvestigator revalidates model registration, metadata/version, input,
and incident binding at execution time. Registry drift yields BLOCKED rather
than a silent model upgrade. The coordinator does not load handlers or artifacts.

FAILED and BLOCKED execution outcomes are ordinary history. Earlier valid
Evidence/signals survive; remaining budget permits a new planner decision.
Selecting another capability is explicit replanning, not automatic fallback.
No operation is silently retried. Partial AI history and its successful signals
remain available even when a later step in that history failed.

Invalid LLM output, repeated plans, transport errors, and coordinator invariant
failures stop the run with `BoundedInvestigationError`. Its `session` preserves
accepted earlier progress and a fatal round with `failure_stage` and `error_type`.
Invalid initial context yields `session=None`. The original exception is chained;
this is not a sanitized traceback interface. No failed planning call is retried.
An invalid returned execution snapshot is not accepted into accumulated state;
external execution may already have occurred and is not rolled back.

Async cancellation propagates unchanged. There is no durable recovery or partial
session delivery on cancellation, no resume protocol, and no new timeout system.

## Verification and limitations

Deterministic tests compose the real planner, registries, governed executor,
Tool orchestrator, and AI investigator with MockLLM/MockTool/MockSecurityAI.
AI → Tool → Ready and Tool → AI → Ready verify updated context on each round,
source provenance, immutable inputs, and absence of automatic assessment/approval.
Failure, blocking, drift, exact-repeat rejection, invalid context, and hard budget
limits are also exercised. These tests verify boundaries, not LLM intelligence.

Evidence raw_data remains excluded from replanning prompts. The existing Tool
Evidence converter emits a generic summary, so a reputation value present only
in raw_data is not visible to the replanner. A future explicit safe summary
projection is needed before claiming that an LLM reasons about those values.

Snapshots are in-memory validated records, not cryptographic attestations or
persistence. Cross-session budget/history integrity is the caller's responsibility.
The existing 64,000-character planner context limit still applies. No fusion,
automatic ThreatAssessment, response, incident closure, queues, parallel execution,
training, or self-improvement is introduced.

For Phase 3, implement real models behind the existing SecurityAI input/output
contract and register them normally. Versioned metadata and execution revalidation
then apply without changing this loop. Feature extraction, validated summaries,
input provenance, resource limits, and model evaluation should be addressed
explicitly before replacing mocks with operational models.
