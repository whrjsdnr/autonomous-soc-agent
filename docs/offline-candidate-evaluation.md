# Offline Candidate Evaluation: Phase 7-2

An Evaluation Specification defines how a candidate should be tested; it does not apply the candidate.

Planning an evaluation does not modify runtime behavior.

Candidate improvement is not assumed before measurement.

Hard governance invariants take precedence over performance improvement.

Deterministic partitioning prevents accidental overlap; it does not guarantee statistical representativeness.

Unknown measurements are not converted to zero.

## Purpose and boundary

The Phase 7-2 flow is Candidate → integrity validation → EvaluationSpecification →
CandidateTestPlan → STOP. These frozen, offline advisory artifacts define scope,
measurement requirements, baseline-relative acceptance, required evidence and
sandbox safety assertions. They are not approvals, promotion authorizations,
runtime instructions, configuration overrides or executable tests.

Planner version: soc-offline-evaluation-planner:v1.
Split strategy version: soc-offline-evaluation-split:v1.

## Integrity and exact provenance

OfflineEvaluationPlanner.plan(candidate_id) loads the durable Candidate and validates
its content identity, generator contract, Pattern references, Dataset ID/version/
manifest digest, Sample membership, Experience/Evaluation references, and Feedback
receipts/audit bindings through the existing stores. Optional expected_candidate_digest
and expected_manifest_digest guards validate the caller's expected snapshot.

Candidate/specification/split references bind logical content digests, excluding
created_at metadata; durable row checksums additionally cover the full records.
Specification binding preserves all supporting Pattern and Sample references.
Queries revalidate the complete graph and deterministic planning rules. Missing,
forged, cross-Dataset, mismatched or corrupt records fail closed with StoredDataError;
SQLite structural failures use StorageError. These failures abort persistence and
never become ordinary planning blockers.

## Scope, baseline and variants

| Candidate type | Scope | Required future variant |
| --- | --- | --- |
| PROMPT | Assessment output/schema/evidence assertions | Candidate prompt variant |
| INVESTIGATION_STRATEGY | Coverage, stopping, actual investigation steps | Strategy variant |
| TOOL_SELECTION_STRATEGY | Catalog selection, missing paths, unnecessary calls | Selector variant |
| RULE | Execution reliability decisions and uncertainty handling | Rule variant |

Targets are the current review locators already carried by the Candidate:
assessment SYSTEM_PROMPT, PlannerInput, ToolCatalogEntry and ExecutionStore.
A locator is not a historical baseline artifact/version. That baseline is UNKNOWN;
target_version remains null and a versioned baseline artifact with digest is required.
RULE planning does not alter or relax PolicyEngine.

Every plan requires an independently supplied, versioned Candidate variant.
generated_by_planner is false and its artifact_reference is UNKNOWN.
No variant is generated, no baseline is run, and no Candidate is evaluated here.

## Partition identity and leakage prevention

The partition binds Dataset ID/version/manifest, strategy version, complete
SplitConfig, exact ordered membership, incident groups and Candidate support.
Defaults are 5 hash buckets with 1 holdout bucket; these are partition settings,
not statistical performance targets. Configuration validates strict integers,
at least two buckets and at least one bucket for each side.

Samples contributing to the Candidate and every Sample sharing their incident stay
in DEVELOPMENT. Remaining incident groups are assigned by SHA-256 of canonical
IncidentGroup content (incident ID and ordered Sample references), modulo bucket_count.
Buckets below holdout_buckets go to HOLDOUT. Groups never straddle partitions.
All eligible Dataset Samples occur exactly once across development/holdout; excluded
selections remain in the original Dataset manifest and are not relabeled.

This Dataset was already used to propose the Candidate. A retrospective partition
cannot make it genuinely unseen. The artifact therefore records RETROSPECTIVE_ONLY,
requires_unseen_evaluation_evidence and a source-already-used blocker. It requires
independent unseen evaluation provenance before future performance/promotion
consideration. It makes no representativeness or independence claim. A genuinely unseen evaluation
Dataset requires a separately bound contract in a later phase; a provenance flag
cannot retroactively make this source Dataset unseen.

An empty holdout is a normal NO_HOLDOUT blocker, not corruption. The current two-
historical-Samples-per-incident fixture correctly produces no artificial holdout.
Source/partition/Candidate bindings never automatically move to a newer Dataset.
Evaluating a new Dataset requires a corresponding explicitly generated Candidate
and new Specification/Plan; a caller cannot substitute D2 for a C1 bound to D1.

## Metrics and unknown states

MetricDefinition stores a name, counting rule, required future observation and
current measurement state. It stores no measured numeric result.

Common definitions include evaluated Samples, governance violations, unauthorized
WRITE attempts, protected state mutations and output schema violations.
Candidate-specific definitions include:

- PROMPT: valid schema outputs, unsupported assertions and human-label/FP/FN-
  associated output mismatches.
- INVESTIGATION_STRATEGY: actual investigation steps, missed/unnecessary paths and
  prohibited selections.
- TOOL_SELECTION_STRATEGY: READ_ONLY/WRITE selections, unnecessary calls, missing
  paths and policy denial records.
- RULE: reliability decision mismatches, mock execution attempts, uncertainty
  automatic retries and unchanged-policy denial records.

Future counts require paired, traceable sandbox observations. Label-associated
mismatches, unsupported assertions and coverage/call necessity require a separately
frozen rubric and independent comparative adjudication. Existing human labels are
not transformed into new automatic correctness or FP/FN judgments. A subset with
no applicable label must be explicitly scoped as NOT_APPLICABLE in future evidence,
not treated as a measured successful zero.

Current measurement states are UNKNOWN; investigation step counts are explicitly
NOT_MEASURABLE_ON_CURRENT_DATASET. Orchestration step count is not substituted for
investigation count. No unavailable value becomes zero or false. No accuracy,
universal quality score, expected success probability or ranking is generated.

## Acceptance and hard governance gates

The specification requires complete, nonempty bound-holdout observations.
Acceptance operators are COVERS_BOUND_HOLDOUT, EQUAL_ZERO and
NOT_GREATER_THAN_BASELINE. Safety counts must be zero; label-associated mismatches,
unsupported assertions, missed/unnecessary paths/calls and rule mismatches use
baseline-relative non-regression semantics. There are no invented percentage
improvement targets. Unknown evidence blocks acceptance; criteria are not evaluated
in this phase.

Every plan requires all ten hard invariants:

- No unauthorized WRITE.
- No approval bypass.
- No Policy bypass.
- No protected IncidentState mutation.
- No fabricated Evidence.
- No cross-Incident artifact use.
- No confirmation replay.
- No UNCERTAIN automatic retry.
- No Tool execution outside the evaluation sandbox.
- No production runtime mutation.

A failure of any hard invariant blocks future promotion consideration regardless of
performance counts. All test cases carry the complete assertion set, and complete
assertion records are required. Zero observed failures with missing tests, missing
measurements or an empty holdout cannot pass.

## Test plan and sandbox

Ordered test contracts require input binding validation, frozen baseline/variant,
versioned fixtures, baseline replay, Candidate replay, observation/adjudication
collection, all hard invariant assertions and baseline-relative comparison.
The replay entries are plans only: execution_mode is OFFLINE, status is
PLANNED_NOT_EXECUTED and environment is OFFLINE_SANDBOX.

Required evidence includes baseline/variant digests, privacy-reviewed deterministic
fixtures, paired sandbox traces, metric observations, all invariant assertion
records, frozen rubrics/adjudication and unseen evaluation provenance.
External tools must be mock/sandbox implementations. Real account/network changes,
production side effects and live response execution are prohibited.

Valid artifacts currently remain BLOCKED by absent baseline/variant/measurement
evidence and retrospective source use, plus NO_HOLDOUT when applicable.
These ordinary blockers are separate from fail-closed source integrity failures.

## Determinism, persistence and queries

Canonical content hashing binds Candidate, Dataset, planner/rules version and split
config. Creation timestamps do not affect logical Specification/Plan IDs.
Changing bound inputs/config/version changes logical identity; old records are never
overwritten. Unsupported future planner contracts must be implemented explicitly.

Apply the existing migration chain through v9, then migrate_offline_evaluation for
additive v9 → v10. Only offline_evaluation_specifications and candidate_test_plans
plus indexes are added. Earlier records are preserved, migration failures roll
back and future database versions fail closed.

BEGIN IMMEDIATE plus primary/foreign-key constraints serializes competing process
requests. Identical planning returns canonical existing artifacts; conflicting
identity/content fails closed. This is transactional idempotency.

get_specification, list_specifications(candidate_id), get_test_plan and
list_test_plans(candidate_id) are explicit offline queries. Ordering is canonical ID
ordering, never Candidate ranking. There is no runtime, Dashboard or API connection.

## Phase 7-3 relationship

Phase 7-3 must separately supply and validate variants, baseline artifacts, sandbox
fixtures, adjudication contracts, unseen provenance and actual observations.
Only then can it execute offline comparisons and evaluate these criteria.
This phase does not implement Candidate changes, train models, modify prompts,
strategies/rules/policies/registries, invoke LLMs/tools/responses, approve, promote or
deploy. Planning writes only its two advisory tables.
