# Phase 2-11: Bounded adaptive investigation and replanning

## One decision boundary

AdaptiveInvestigationPlanner interprets current observations, model predictions,
and investigation history to propose one next decision. It does not implement a
repeating agent loop. The adaptive package references both investigation paths and
reuses their existing draft-to-plan converters without changing their public APIs.

```text
Incident + AISignals + Tool/AI history + application budget
    → validated InvestigationContext
    → budget stop OR one structured LLM response
    → semantic ReplanningDraft
    → existing allowlist/schema conversion + duplicate check
    → immutable AdaptiveInvestigationDecision
    → return (no execution)
```

```python
from soc_agent.adaptive import (
    AdaptiveInvestigationPlanner,
    InvestigationBudget,
    InvestigationContext,
)

context = InvestigationContext(
    incident=state,
    signals=signals,
    tool_history=(tool_result.plan,),
    ai_history=(ai_result,),
    budget=InvestigationBudget(max_rounds=5, current_round=1),
)
decision = await AdaptiveInvestigationPlanner(
    llm_client=llm_client,
    tool_registry=tool_registry,
    ai_registry=ai_registry,
).replan(context)
```

Tool history is a tuple of existing InvestigationPlan snapshots (for example,
InvestigationResult.plan); AI history is a tuple of SecurityAIInvestigationResult
snapshots. Caller supplies the latest Tool snapshot once per plan. AI runs have
separate investigation IDs and may represent explicit attempts of a selection plan.

## Decision semantics

| Decision | Meaning / payload |
| --- | --- |
| CONTINUE_WITH_TOOL | Exactly one validated pending InvestigationPlan step |
| CONTINUE_WITH_AI | Exactly one validated SecurityAISelectionPlan step |
| READY_FOR_ASSESSMENT | Advisory readiness; no next plan |
| STOP_INSUFFICIENT | Insufficient information and no useful next proposal; no next plan |
| ESCALATE_TO_HUMAN | Recommend analyst review; no next plan |

READY_FOR_ASSESSMENT does not confirm a threat, resolve or close the incident, or
compute ThreatAssessment. The current ThreatAssessor requires observed Evidence;
a readiness draft without any Evidence is rejected deterministically. This enforces
that existing precondition, not an evidence sufficiency heuristic. The LLM's quality
of readiness judgment is not established by these mock tests.

ESCALATE_TO_HUMAN is an analyst escalation recommendation, not a response approval.
It neither creates an ApprovalManager record nor approves a proposed action.
STOP_INSUFFICIENT also leaves the incident open and unchanged.

## Semantic draft and application-owned output

ReplanningDraft contains decision, a nonblank reason (up to 2000 characters), and
optional tool/ai semantic payloads. CONTINUE_WITH_TOOL requires tool and forbids ai;
CONTINUE_WITH_AI requires ai and forbids tool; all terminal choices forbid both.
The payloads reuse LLMInvestigationStepDraft and SecurityAISelectionStepDraft.
All levels forbid extras. Metadata, IDs, permissions, risk, approval, severity,
status, and budget cannot be supplied by the LLM as decision metadata.

The application generates decision_id, incident_id, created_at, and next plan IDs.
AdaptiveInvestigationDecision is frozen, includes the application budget snapshot,
and checks that any next plan has one step bound to the same incident. Tool steps
must be pending. Nested canonical inputs are immutable via existing plan models.
Reason and purpose remain untrusted explanations, never authority.

The Tool path calls the existing planning.validator.normalize_plan. The AI path
calls security_ai.selection_validator.normalize_selection with a single RUN_AI
selection. Those functions own exact name lookup, model/tool input schema checks,
defaults/aliases, canonical JSON conversion, and application ID assignment. There
is no second implementation of those rules and no extra LLM call to either planner.

## Read-oriented capability catalogs

Registry lists are snapshotted before awaiting the LLM; the same mappings feed the
catalog and plan validation. Newly registered models/tools during that await are
not eligible for the current decision. Names require exact matches. Unknown or
excluded capabilities fail without fuzzy matching, fallback, retry, or execution.

The original InvestigationPlanner accepts all registered Tools and defers governance
to execution. Adaptive investigation intentionally exposes only observation-oriented
capabilities using the existing ToolMetadata.is_read_only_capability property:
read permission plus READ_ONLY or LOW risk. Verification already uses this property.
It is a domain capability filter, not a duplicate PolicyEngine or name-based heuristic.
Response-capable, HIGH, and DESTRUCTIVE Tools are not advertised and cannot be selected.
The converter also applies this predicate when called directly with a wider mapping.

Tool catalog projection reuses build_planner_input(...).tools. AI catalog projection
reuses build_security_ai_catalog. Both sort by name and include public metadata and
input schema, without handlers, repr, or artifact objects. Public schema defaults,
descriptions, and metadata must themselves be reviewed for sensitive content.
This is not a redaction system. SecurityAI selection confers no response authority.

Future execution still must pass the existing governed Tool executor. A Tool plan
does not pin metadata or preserve this capability filter for an arbitrary future
registry; a future adaptive coordinator must recheck read-only scope at execution.
The separate SecurityAIInvestigator already revalidates its AI plan at execution.

## Context validation and privacy

At least one Evidence, AISignal, Tool history, or AI history snapshot is required.
An empty incident belongs to initial planning, not this boundary. Every call first
revalidates and detaches context, including nested snapshots made via Pydantic bypass
APIs. Invalid context is rejected even if its budget is exhausted.

Tool/AI history must belong to the current incident. Tool plan IDs, Tool step IDs,
and AI investigation IDs cannot be duplicated in their history collections.
Completed Tool Evidence references must exist in the current state. Existing AI
snapshot validators check their result/signal links. The unchanged Phase 2-8 context
builder checks signal incident, Evidence references, and duplicate signal/result IDs.

Signals are collected from explicit context.signals and completed AI history.
An identical signal present in both representations is included once; conflicting
copies with the same signal ID fail. Duplicate explicit signals still fail, and
separate signals with a duplicate source_result_id fail. Order is explicit signals
first, followed by new history signals in supplied history order.

A blocked AI history may retain invalid source references as the reason it was
blocked. These unexecuted references are not promoted into signals or accepted as
Evidence provenance. Reference validation establishes consistency, not cryptographic
authenticity or proof that model features came from those records.

The prompt projects separate JSON sections:

- OBSERVED EVIDENCE: ID, source, summary, observed_at; excludes raw_data.
- OBSERVATIONS: statements and Evidence references.
- AI SIGNALS: Phase 2-8 prediction/provenance representation, explicitly not facts.
- HYPOTHESES: uncertain interpretations, confidence, and references.
- TOOL INVESTIGATION HISTORY: capability/purpose/status, IDs, Evidence ID, error type.
- AI INVESTIGATION HISTORY: model/version/purpose/status, run/step/result/signal IDs,
  error type.
- Available catalogs and the application budget.

History inputs remain available for application duplicate checks but are not copied
to the prompt. Raw ToolResult, raw AI input, failure messages, and tracebacks are not
included. Only error_type is projected; it and every incident/model-derived string
are treated as untrusted JSON data. System instructions explicitly separate observed
facts, predictions, hypotheses, and planned/attempted history. This does not prove
that a real LLM is immune to semantic prompt injection; allowlist/schema/output
validation remains the deterministic boundary.

The complete serialized user context has a 64000-character cap, including history,
AI explanations, and catalogs. Oversized context fails before calling the LLM, with
no silent truncation or dropping of evidence. This is a submitted character budget,
not a token estimator or peak-memory bound. Identical ordered context and catalogs
produce identical serialized requests; generated output IDs/times are not inputs.

## Budget and empty-catalog policy

InvestigationBudget is frozen, strict, and application-controlled. max_rounds defaults
to 5, current_round to 0. current_round denotes previously consumed replanning rounds.
Negative values, booleans/coercive strings, and nonpositive limits are rejected.
When current_round >= max_rounds, a validated context returns ESCALATE_TO_HUMAN with
reason "Investigation budget exhausted" and zero LLM calls. No continuation plan is
created. The LLM cannot increase or reset the budget.

A future caller/coordinator owns incrementing and retaining current_round, including
unsuccessful LLM planning attempts. This stateless planner does not enforce a durable
or cross-call counter, and cannot prevent a trusted caller from resetting progress.

If both eligible catalogs are empty and budget remains, one LLM call is allowed to
choose readiness, insufficient information, or escalation. No heuristic presumes
that lack of tools implies insufficient evidence. A continuation hallucinating a
capability fails against the empty snapshot.

## Exact repetition and explicit alternatives

After canonical validation of a next step, compare it against supplied history:

- Tool: tool_name + canonical tool_input.
- AI: model_name + canonical model_input from each execution selection snapshot.

An exact duplicate is rejected, regardless of purpose, status, or additional textual
reason. This includes pending, blocked, and failed history, preventing accidental
re-enqueueing or automatic retries. AI version is intentionally not part of the key
in this phase: same name/input is still repetitive. A different input for the same
capability is allowed because it may investigate a different entity or observation.

A failed auth_anomaly followed by an LLM draft explicitly selecting network_anomaly
is a new validated replanning decision. It is not automatic fallback: the system
never substitutes a model when another fails, nor calls one during replanning.

The comparison is exact JSON equality against recorded canonical inputs, not semantic
equivalence or freshness analysis. It relies on caller-supplied complete history;
historical defaults/schema versions are not reconstructed. AISignals alone lack
input fingerprints, so they cannot establish exact prior input identity. The LLM
may propose a repeat because raw history inputs are omitted, in which case validation
fails without another LLM attempt. Legitimate repeated measurements require a later,
explicitly designed freshness/override policy; there is no exception mechanism here.

## Failure and execution boundaries

InvalidInvestigationContextError and AdaptiveContextTooLargeError fail before the
LLM. RepeatedInvestigationError rejects a repeated next step. Existing Tool/AI
normalizer errors retain their types for unknown names and invalid inputs.
LLMResponseValidationError handles inconsistent/forged drafts; LLM transport errors
and cancellation propagate. No failure triggers a hidden retry or partial plan.
Public context error messages omit raw values; chained validation errors may contain
sensitive data and should not be published as tracebacks.

This package calls no Tool, SecurityAI inference, ThreatAssessor, ResponsePlanner,
PolicyEngine, or ApprovalManager. It has no direct dependency on response, approval,
policy, or verification. IncidentState, AISignals, histories, and supplied budget
remain unchanged. Readiness and escalation are returned to the caller because
assessment and response remain separately controlled workflows.

## Future bounded loop

A later small coordinator can:

1. Own a persistent application budget and complete history.
2. Invoke this planner once and account for the round even if planning fails.
3. For continuation, revalidate and invoke the appropriate existing executor.
4. Retain new Evidence or separate AISignals and explicit failure history.
5. Re-enter planning only within budget; stop on readiness/insufficient/escalation.
6. Invoke ThreatAssessor separately for readiness, never from this planner.

No such loop, automatic execution, adaptive retry, multi-model fusion, real ML model,
training, outcome decision, or self-improvement is implemented here. No dependency
or existing public API was changed. Tests measure semantic contracts, not real LLM
security intelligence.
