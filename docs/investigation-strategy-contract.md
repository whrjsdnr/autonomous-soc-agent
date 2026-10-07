# Investigation strategy contract — Phase 7-5A

An investigation strategy constrains planning; it does not authorize execution.

Previously the offline adapter selected an explicit permission tuple while the
production planner generated tool names and inputs from an LLM. Coverage selection
alone could not prove that production could construct a valid investigation plan.
The new contract shares the interpretation and validation of required coverage;
it does not claim that the offline adapter reproduces production planner output.

## Declarative contract and compiler

`InvestigationStrategy` is immutable, rejects extra fields, and supports only
`REQUIRE_READ_ONLY_PERMISSION_COVERAGE`. Its nonempty `required_permissions`
contains only `SYSTEM_READ`, `NETWORK_READ`, or `FILE_READ`. Duplicate permissions
are removed and ordering is canonical. Empty constraints are rejected as candidate
strategies; no constraint is represented separately by `None`.

`compile_candidate_strategy` revalidates the candidate's content identity and
compiles only its existing structured `CoverageProposal.required_permission`.
REVIEW, PROMPT, RULE, and TOOL_SELECTION_STRATEGY proposals are unsupported.
Candidate text, rationale, or expected effect never supplies execution semantics.
The compiler and canonical coverage relation are shared by production validation
and offline evaluation. No code, tool names, inputs, or prompts are generated.

## Production integration

An explicitly injected `InvestigationStrategyProvider` supplies a constraint once
per planning call. `ExplicitStrategyProvider` provides a revalidated immutable
constraint or `None`; there is no database, registry, or active-version lookup.
Without a strategy, existing planner behavior and request context remain unchanged.

Before the LLM call, the planner checks that the trusted catalog has read-only
capabilities capable of satisfying the constraint. Missing capabilities raise
`UnsatisfiableStrategy`. A tool's permission alone is insufficient if its risk
metadata does not qualify as a read-only capability.

The LLM is then called once. Existing `normalize_plan` verifies catalog membership
and tool input schemas. `validate_strategy` revalidates the resulting plan and
inputs and uses actual registered `ToolMetadata.is_read_only_capability` values.
Missing required coverage raises `StrategyCoverageError`. The validator neither
adds steps nor repairs inputs, retries the LLM, or executes tools. Existing runtime
incident/evidence-reference checks and execution governance remain responsible
for their existing boundaries. A coverage constraint is not a general permission
to execute other steps in a plan.

Offline coverage improvement is not evidence that the production LLM planner will generate a correct plan.

## Versioned offline safety evidence

The original v2 evaluator remains available with its unchanged UNKNOWN downstream
gate results. Explicitly requesting `soc-offline-candidate-evaluator:v3` records
`StrategySafetyEvidence` in the existing immutable result payload. No schema change
is required. New absent fields are omitted from legacy serialization so existing
result identities and review snapshots remain valid. Store replay validates the
exact evaluator version and the corresponding source graph.

v3 uses the same compiled candidate constraint. Coverage counts still compare
explicit offline baseline paths and candidate-required paths against provenance-
bound human holdout requirements. They do not measure production tool executions
or LLM-generated plan quality. HOLDOUT cases, source bindings, and incident-based
leakage separation remain unchanged. Unknown human requirements remain unknown.

For safety, a fixed local fixture catalog creates validated sandbox plan drafts.
Its names and empty input schemas are explicit test fixtures, not fabricated
production tools or reconstructed historical inputs. The production normalizer,
strategy validator, real `PolicyEngine`, and shared `GovernedExecutor.preflight`
observe these gates without dispatch:

- Read-only fixture operations are allowed by the policy and preflight.
- Destructive WRITE is denied by both policy and preflight.
- Low-risk WRITE requires approval and fails preflight without one.
- An unrelated, unregistered approval ID fails the Tool Approval lookup.
- No Approval request is created and no Tool is executed.

`execute` rechecks this same preflight before reserving an attempt or dispatching.
Preflight success is not a durable authorization or reusable execution token.
The strategy itself has no executor, policy override, approval, confirmation,
state mutation, response execution, or external IO capability.

Policy/Approval PASS or FAIL is scoped to these recorded deterministic gate probes.
It does not assert exhaustive safety of production tools, policies, human sessions,
or every possible planner output. Existing capability-absence and bound-trace
invariants retain their original meanings. Other unobservable behavior is not
invented: real investigation step counts remain NOT_MEASURABLE. Unnecessary paths remain
NOT_MEASURABLE without explicit COMPLETE human path adjudication (Phase 7-5A.2);
missing evidence leaves the applicable acceptance result UNKNOWN.

Safety UNKNOWN is resolved only when the corresponding invariant is actually observed.
Human Improvement Review approval is not Tool Approval.

## Review and eligibility boundary

New v3 result IDs produce a new comparison and a new review request. Existing
review requests and human records are never overwritten. Human Review policy is
unchanged: any FAIL or UNKNOWN required acceptance/safety evidence blocks APPROVE.

The existing read-only promotion eligibility gate now recognizes the production
constraint contract only for a source-validated v3 result whose explicit strategy
matches the compiler and whose sandbox plan validation passed. It does not infer
that legacy v2 selections validated production planning. Actual review, safety,
and acceptance blockers still determine eligibility. Legacy v3 coverage results without COMPLETE path adjudication retain UNKNOWN
required acceptance and remain NON_PROMOTABLE. New COMPLETE evidence can satisfy
that criterion; eligibility still requires all gates and an explicit trusted human
APPROVE. Adjudication and eligibility do not activate any production version.

Phase 7-5A introduces no active-version mutation.

Registry, promotion authorization, activation, bootstrap, and rollback belong to
7-5B. No promotion request, permission, or confirmation is introduced here. An
offline `FrozenBaseline` remains an explicit offline configuration, not an
inferred historical or current production strategy. Production LLM output is not
claimed deterministic; the typed compiler, validators, and local offline probes
are deterministic.

The declarative strategy → validated plan → policy → human governance → execution
boundary is independent of incident-specific version-registry storage. No future
Harness, server, fleet, or deployment architecture is introduced.
