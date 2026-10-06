# Offline Candidate Comparison (Phase 7-3)

Offline Candidate Variants are evaluation artifacts, not runtime configuration.
A candidate is not assumed to be implementable.
Baseline and Candidate results must use the same frozen evaluation cases.
Performance improvement cannot override a failed governance invariant.
Offline evaluation results do not authorize promotion.
UNKNOWN is not treated as PASS.

## Supported vertical slice

Candidate → explicit FrozenBaseline → isolated Variant → frozen HOLDOUT cases →
paired deterministic permission-coverage replay → factual counts/deltas → STOP.

REVIEW proposals remain non-executable.
Only explicitly structured allowlisted proposals can become offline variants.
Unsupported candidate types remain NOT_CONSTRUCTIBLE.

The only executable family is INVESTIGATION_STRATEGY with operation
REQUIRE_READ_ONLY_PERMISSION_COVERAGE. It requires one explicit permission from
SYSTEM_READ, NETWORK_READ or FILE_READ, the existing observation-only categories
of ToolPermission. The target is the PlannerInput investigation contract. The
operation adds that permission to the frozen offline configuration's covered paths;
existing paths remain present. It is not a tool call, LLM instruction, code patch,
policy change or production strategy update. There are no invented tool names.

The existing Phase 7-1 generator still produces only REVIEW proposals. An explicit
`ImprovementCandidateStore.declare_coverage_proposal(review_candidate_id,
required_permission=...)` creates a separate advisory candidate. It binds an exact
MISSED_INVESTIGATION strategy REVIEW parent, Pattern, Dataset and supporting refs.
The v2 candidate schema and declaration version distinguish caller-supplied
parameters from pattern-generated reviews. Rationale and expected_effect text
have no execution semantics. Dataset facts never choose a parameter automatically.
PROMPT, RULE and TOOL_SELECTION_STRATEGY remain unsupported for execution.

## Explicit frozen baseline

FrozenBaseline is an explicit offline snapshot, not an inferred historical baseline.

`capture_baseline(target_reference=..., configuration=CoverageConfiguration(...))`
requires both arguments. Only the allowlisted PlannerInput target and versioned
permission-coverage adapter contract can be captured. The caller provides the
canonical read-only path configuration; capture does not inspect production state,
load a current production planner as historical behavior, invoke LLMs, or select a
baseline automatically. The snapshot binds configuration, target, adapter version,
the existing ToolMetadata read-only permission reference, and explicit
EXPLICIT_OFFLINE_CONFIGURATION_NOT_HISTORICAL provenance. Its ID/version are
canonical content hashes; created_at is metadata.

`OfflineEvaluationRunner.evaluate(plan_id, baseline_id=..., expected_baseline_digest=...)`
pins that exact snapshot. A baseline ID never resolves to a newer snapshot. A
missing ID/digest, corrupted snapshot or wrong target fails closed. Omitting the
baseline ID retains BASELINE_UNAVAILABLE and NOT_EXECUTED, even if the database
already contains suitable snapshots. Specification's historical UNKNOWN is retained:
the later explicit offline snapshot fulfills an artifact requirement; it does not
rewrite the historical reference or pretend to reconstruct the historical runtime.

## Ground truth, provenance and holdout

Candidate → Pattern → Dataset → Sample → Evaluation/Feedback and confirmation/audit
receipts are verified before evaluation. Specification, Plan and the canonical
incident-group split are rederived. Tampering, forged membership, cross-dataset
support and development/holdout overlap are integrity errors, not unavailable runs.

Cases bind the exact frozen holdout sample and safe source refs, existing human
verdict/labels, metrics and explicit coverage facts. DEVELOPMENT samples and every
supporting incident stay outside evaluation. Both arms use the same complete cases,
ordering, metric definitions, baseline binding and sandbox assumptions.

An overall MISSED_INVESTIGATION label does not identify a required permission.
Optional typed `FeedbackRequest.coverage_expectation` therefore carries an explicit
human-required read-only path fact. It requires conclusive feedback, canonical
permissions and the existing authenticated submission, confirmation receipt and
audit chain. This positive fact can accompany CORRECT or INCORRECT verdicts; the
adapter never changes either verdict. Plain-text notes are never interpreted.

Only expectations from the snapshot's contributing Feedback refs are used. Positive
requirements are unioned canonically and their exact refs appear in each frozen case.
No expectation means NOT_MEASURABLE. If any holdout case lacks required coverage
facts, the aggregate missing-path metric is NOT_MEASURABLE rather than counting
that case as zero or silently excluding it. Late Feedback requires Dataset rebuild,
new Candidate and new Plan; older case/result bindings remain intact.

The analyzer groups all MISSED_INVESTIGATION-labeled samples into supporting
patterns. Those samples therefore remain DEVELOPMENT. Measurable HOLDOUT fixtures
use other incidents with independently explicit human coverage facts; they are not
relabelled as MISSED_INVESTIGATION. `missed_investigation_path_count` measures paths
missing from these frozen requirements, not newly adjudicated incident correctness.

Deterministic partitioning prevents accidental overlap; it does not guarantee
statistical representativeness. The source dataset remains RETROSPECTIVE_ONLY.
Results do not establish independent unseen evaluation evidence.

## Pure offline adapter and measurements

Offline adapters cannot mutate production runtime.

The adapter accepts only immutable case/configuration data and returns selected
permission paths, required paths and their set difference. It has no Orchestrator,
State, Evidence factory, Tool/Response executor, Approval/Confirmation consumer,
Policy engine, callbacks, registry, network, account or filesystem handles. It
executes no real tool and invokes no external LLM. The result is the behavior of a
small declarative coverage adapter, not measured production planner/model performance.

Paired executed results retain per-case traces and bind Candidate, Variant,
Specification, Plan, Dataset, manifest, split and FrozenBaseline. Measured metrics
are limited to specified definitions supported by observations:

- evaluated_sample_count: complete paired case traces;
- missed_investigation_path_count: missing human-required permission paths;
- output_schema_violation_count: violations of the frozen read-only selection schema;
- unauthorized_write_attempt_count: observed WRITE permission selections;
- protected_state_mutation_count: zero from the adapter's absence of mutation capability.

Actual tool invocation, investigation step, unnecessary-path and unsupported
correctness metrics remain NOT_MEASURABLE. Unknown measurements are not converted
to zero. Aggregate governance counts remain UNKNOWN when required downstream gate
assertions are unobservable. No new metric, accuracy, precision, recall, F1,
probability, overall candidate quality or rank is introduced.

## Safety and acceptance

Unobservable safety invariants remain UNKNOWN.

Eight safety invariants can be checked from bound traces or the pure adapter's
absence of production capabilities. Observed WRITE selection fails its assertion;
a mismatched case trace fails cross-incident binding. No protected state mutation,
Evidence fabrication, Confirmation replay, automatic UNCERTAIN retry, sandbox Tool
escape or production side effect is possible through the adapter interface.

Actual downstream Policy/Approval enforcement is not exercised by this declarative
adapter, so NO_POLICY_BYPASS and NO_APPROVAL_BYPASS remain UNKNOWN. Each decided
assertion records its basis. Capability-based PASS applies only to this offline
adapter and cannot establish production governance correctness. Observer fault
fixtures test FAIL handling without making production calls or injecting callbacks
into the durable runner.

The unchanged Phase 7-2 criteria are evaluated mechanically as PASS/FAIL/UNKNOWN.
Known counts support EQUAL_ZERO, NOT_GREATER_THAN_BASELINE and nonempty complete
COVERS_BOUND_HOLDOUT; missing observations keep UNKNOWN. Per-metric improvement
and hard safety failures remain separate. There is no approval or promotion verdict.
Measured improvement does not authorize promotion.

## Determinism, persistence and query

Legacy unavailable artifacts retain builder/evaluator v1. Executable coverage
artifacts use:

- soc-offline-coverage-proposal-declaration:v1
- soc-offline-candidate-variant-builder:v2
- soc-offline-candidate-evaluator:v2
- soc-offline-permission-coverage-adapter:v1
- soc-baseline-candidate-comparator:v1

Canonical content hashes bind all logical inputs, including frozen baseline and
human ground truth; creation timestamps are outside logical identity. Repeated
planning/replay returns existing canonical artifacts including original timestamps.
BEGIN IMMEDIATE and primary keys serialize independent process requests. No
artifact overwrite is permitted.

The v10 → v11 variant/result/comparison tables remain intact. Explicit v11 → v12
adds only `frozen_offline_baselines`: an independent reusable baseline cannot fit
the v11 tables' mandatory Candidate/Plan foreign keys. Original records and the
migration chain are preserved; migration rollback and future schema rejection
remain fail closed. Existing absent optional fields serialize exactly as before,
preserving old Feedback and unavailable artifact digests.

Queries revalidate durable sources, frozen baseline, deterministic execution and
pinned offline parent records. get_baseline, get/list variants, get/list results and
get/list comparisons remain offline-only. No runtime, Dashboard or API integration
is added.

## Unavailable paths and Phase 7-4

REVIEW, unsupported types and missing baseline retain the safe NOT_EXECUTED path.
Empty holdout remains blocked. Unsupported human ground truth produces an executed
selection trace with NOT_MEASURABLE correctness-associated measurements.

These artifacts are advisory only. No production prompt/strategy/rule/policy/model/
registry mutation, Tool/Response execution, approval creation or promotion occurs.
Phase 7-4 may review factual results, limitations and unresolved safety assertions;
it cannot treat UNKNOWN or retrospective coverage improvement as promotion-safe.
