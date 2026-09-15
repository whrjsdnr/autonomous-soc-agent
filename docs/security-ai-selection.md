# Phase 2-9: Agentic Security AI selection

## Why selection is reasoning

An incident can justify different analytical models depending on observed data and
remaining uncertainty. The agent proposes which available models could help, their
inputs, and their purpose. Deterministic application code validates those proposals.
Mock tests verify contracts and boundaries, not the quality of LLM reasoning.

```text
Incident summaries + Observations + Hypotheses + Existing AISignals
    + Registry catalog snapshot
    → one structured LLM call
    → SecurityAISelectionDraft
    → exact allowlist and input schema validation
    → immutable SecurityAISelectionPlan
```

LLM selects. Application validates. Registry authorizes availability. SecurityAI
executes only when a future, separate coordinator explicitly invokes its wrapper.
The current selector does not perform inference.

## API and ownership

```python
from soc_agent.security_ai import SecurityAISelector

selector = SecurityAISelector(llm_client=llm_client, registry=registry)
plan = await selector.select(incident=state, signals=existing_signals)
```

The constructor follows InvestigationPlanner's dependency injection pattern. The
selector snapshots registered wrappers before awaiting the LLM and uses the same
read-only mapping for catalog generation and validation. Models registered during
the LLM call cannot become eligible for that call. Definitions and Pydantic schema
code are trusted application setup, not an execution sandbox.

| Owner | Fields / decisions |
| --- | --- |
| LLM draft | decision, goal, reason; model_name, model_input, purpose per selection |
| Registry | available exact names, implementation, version, task_type, input_type, input schema |
| Application | plan_id, step_id, incident binding, UTC created_at, validated input snapshot |

Draft schemas forbid extras at both levels. The LLM cannot supply version, task,
input type, result/signal/plan/step IDs, incident_id, status, risk, permissions,
approvals, policy, predictions, or confidence as selection metadata. A model's own
input schema still defines its legitimate feature keys; selection metadata rules
do not ban arbitrary feature names inside model_input.

A SecurityAISelectionStep copies identity/version/task/input type from the selected
registry wrapper. The plan incident_id comes from the revalidated IncidentState.
Plan and step IDs are application-generated UUIDs; created_at is timezone-aware UTC.
Purpose and reason remain unverified LLM reasoning, with no authority attached.

## Decisions and bounds

SecurityAISelectionDecision serializes as `run_ai` or `no_ai_needed`, following the
project's lowercase enum convention:

- RUN_AI: 1–5 ordered selections.
- NO_AI_NEEDED: zero selections and a nonblank goal/reason.

Both draft and plan enforce decision/list consistency. Goal, reason, and purpose
are bounded to 2000 characters. NO_AI_NEEDED means the selector proposes no further
AI analysis in this pass. It does not establish that the incident is benign,
complete, or closed. The reason may also describe insufficient usable input; no
features should be invented to force a model call.

An empty registry fails deterministically before calling the LLM, consistent with
the existing Tool planner. There is no recursive selection, retry, fallback, or loop.

## Catalog and context

build_security_ai_catalog sorts by exact name and projects only public metadata
(name, version, description, task_type, input_type) and Pydantic input JSON schema.
It never serializes wrappers, handlers, Python repr, artifact paths, or internal
objects. Output schema is omitted because selection only requires input contracts.
Schema descriptions/defaults and registry descriptions must be reviewed as public
prompt-facing content; the builder is not a secret detector or redactor.

The request explicitly projects incident ID/status/severity, Evidence IDs/sources/
summaries, Observation statements/references, and Hypothesis statements/confidence/
references. It excludes Evidence.raw_data to minimize disclosure and unnecessary
context for model selection. Required input facts must come from supplied context;
schema validation cannot prove they are semantically supported by that context.

Existing AISignals are serialized through the unchanged Phase 2-8
build_ai_signal_context. Source result IDs, model/version/task, predictions,
confidence, scores, explanations, and Evidence references remain separate from
observed facts. Unknown Evidence, cross-incident signals, and duplicate signal/result
IDs fail before any LLM call. Historical models need not still be registered to
appear as signals; only new selections require membership in the current catalog.

Context serialization is deterministic for the same snapshots. The complete JSON
user context, including model schemas and AI explanations, has a 64000-character
limit. Oversized context is rejected without truncating facts or silently dropping
signals/models. This bounds submitted text, not peak serialization memory or provider
token consumption. System instructions and the structured response schema are not
part of this character count.

Incident and AI explanation text remains inside JSON data. Trusted system instructions
explicitly forbid following embedded instructions and treating predictions as facts.
If a hostile summary persuades an LLM to select admin_model, exact registry validation
still rejects an unregistered model. JSON separation is not a guarantee against all
semantic influence on a future real LLM.

## Input validation and atomicity

After the single structured response, normalization detaches and revalidates the
draft. Every exact model name must exist in the request's snapshot; there is no fuzzy
matching, dynamic model loading, registry mutation, or automatic substitute.

Each input is validated against the selected Pydantic input model with extra fields
forbidden. Defaults, coercion rules, and aliases follow that model. The validated
input is serialized with aliases in JSON mode and frozen using the shared
soc_agent._json.canonical_json_object. It is then checked against the same
SecurityAIRequest envelope used by the inference wrapper, without calling predict.
Inputs that cannot survive this JSON-to-envelope round trip are rejected.

Within a plan, the same model name plus the same canonical validated input is a
duplicate and rejects the whole plan. Defaults and coercion therefore participate
in duplicate detection. Different inputs for the same model are allowed. JSON
canonical equality is not a universal semantic equivalence relation for features.
Selection ordering is preserved. One invalid selection invalidates the entire pass;
no partial plan or inference side effects are returned.

Plan/step snapshots are frozen; nested input is canonical text, and input_payload()
returns a fresh decoded object. Direct model construction/deserialization validates
shape, not registry authenticity. As in earlier phases, arbitrary trusted Python
and Pydantic bypass APIs are outside the provenance guarantee.

## Failure semantics

- NoSecurityAIAvailableError: empty registry; zero LLM calls.
- InvalidAISignalContextError: invalid signal provenance/context; zero LLM calls.
- SelectionContextTooLargeError: user context exceeds the bound; zero LLM calls.
- UnknownSelectedModelError: name absent from the fixed allowlist.
- InvalidSelectedModelInputError: model schema or JSON round-trip failure.
- SecurityAISelectionError: duplicate model/input selection; common deterministic root.
- LLMResponseValidationError: invalid structured draft, including forged metadata.
- Other LLM errors and cancellation propagate unchanged.

Malformed IncidentState uses its existing Pydantic ValidationError. No failure
triggers a retry or fallback. Public error messages do not copy supplied input;
exception causes can contain sensitive validation details and need controlled logging.

## Execution separation and Phase 2-10

The selector's only external I/O is its injected LLMClient. It has no inference,
Tool, Policy, Approval, Response, or ThreatAssessment operation. SelectionPlan is
an analytical proposal, not permission to block IPs, disable users, or change state.
Tests assert every registered MockSecurityAI call_count remains zero across successful
selection, multiple models, invalid input, hallucinated models, and malicious text.

A future coordinator can consume the ordered steps, validate the plan incident and
current registry metadata against the snapshot, revalidate inputs, and invoke the
SecurityAI wrapper explicitly. It should bind returned results to source Evidence
and use create_ai_signal, with execution budgets, failure handling, and audit records.
Plan existence alone must not bypass those future execution checks.

Execution-time provenance, verified feature extraction, input fingerprints, and
source Evidence binding for newly proposed input remain future work. AISignal does
not retain raw input, so this phase intentionally does not deduplicate selections
against historical signals or prove that LLM-proposed values came from Evidence.

Tool/AI unified investigation, adaptive replanning, fusion, weighted voting, real
models/training, response changes, incident outcomes, and self-improvement remain
deferred. No dependencies or existing runtime/planner/assessor APIs are changed.
