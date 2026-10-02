# Governed self-improvement: Phase 7-1

Phase 7 architecture is Observe → Learn → Propose → Evaluate → Approve → Promote.
Phase 7-1 implements only the offline Learn → Propose boundary:

Improvement Dataset → Failure Pattern Analysis → Improvement Candidate → STOP

Failure patterns are observations, not proven root causes.

Improvement Candidates are advisory artifacts, not runtime instructions.

Candidate generation does not modify prompts, policies, models, tools, or runtime behavior.

Every candidate requires offline evaluation before it can be considered for promotion.

Candidate generation does not predict improvement success.

## Analysis inputs and minimum support

The caller explicitly chooses one immutable Dataset ID. Before analysis, durable
queries validate Dataset identity, manifest digest, exact membership, Sample source
bindings, Experience/Evaluation integrity, Feedback receipts and audit bindings.
An optional expected_manifest_digest guards a caller's expected snapshot.

Analysis uses only Sample verdicts, diagnostic labels, objective workflow,
governance/execution outcomes and analysis/fusion presence. Recovery,
uncertain_observed and reconciliation_observed come from each Sample's exact pinned
Evaluation reference. It does not consult newer feedback or runtime context.
No raw payload, analyst note, authentication material, prompt text or CoT is copied.

Analyzer version is soc-failure-analyzer:v1. AnalysisConfig defaults
minimum_pattern_support to 2 and validates a strict integer at least 2.
The complete configuration is bound into each pattern's content identity.
Below-threshold observations produce no repeated pattern; source Samples remain intact.
Support counts are Sample counts, not independent-incident counts: multiple historical
Samples can belong to the same incident.

## Patterns and causality

Supported types are INCORRECT, FALSE_POSITIVE, FALSE_NEGATIVE,
UNNECESSARY_INVESTIGATION, MISSED_INVESTIGATION, EXECUTION_FAILURE,
EXECUTION_UNCERTAINTY and RECOVERY patterns.

Diagnostic patterns preserve human labels. INCORRECT records the human verdict;
it does not invent new correctness judgments. Operational patterns preserve
existing failed/uncertain outcomes and recovery facts, even when an analyst labeled
the overall Sample CORRECT. They do not recategorize that verdict.
Historical uncertainty and a later successful outcome can coexist.
Human rejection alone creates no pattern or candidate.

Each frozen FailurePattern binds the Dataset ID/version/manifest, analyzer/config,
canonically ordered Sample references, all contributing Feedback references and
per-Sample observed facts. Occurrence count is checked against support. Scope is
overall and root_cause_status is always UNKNOWN. No classifier-specific association,
attack cause, threshold defect or analyst intention is inferred from these facts.

## Structured advisory generation

Generator version is soc-improvement-candidate-generator:v1.
Fixed deterministic review mappings are:

| Pattern | Review candidate types |
| --- | --- |
| INCORRECT / FALSE_POSITIVE | PROMPT |
| FALSE_NEGATIVE | PROMPT and TOOL_SELECTION_STRATEGY |
| UNNECESSARY_INVESTIGATION | INVESTIGATION_STRATEGY |
| MISSED_INVESTIGATION | INVESTIGATION_STRATEGY and TOOL_SELECTION_STRATEGY |
| EXECUTION_FAILURE / EXECUTION_UNCERTAINTY / RECOVERY | RULE |

The review focus is an opportunity category, not an attributed cause.
Candidates from distinct patterns remain separate even when they share a target.
An opportunity is represented by the structured proposal and rationale; no separate
persisted opportunity layer is needed.

Typed proposals contain a fixed target component/reference, operation REVIEW,
review focus and proposed guidance, coverage, constraint or rule-description review.
Targets refer to current known interfaces: assessment SYSTEM_PROMPT, PlannerInput,
ToolCatalogEntry and ExecutionStore. These are review locators, not proof that a
specific implementation/version caused a historical failure. The Dataset does not
record historical prompt/strategy versions, so target_version stays null.
RULE reviews concern execution failure/recovery handling, not PolicyEngine rules.
Every proposal explicitly retains existing security/approval boundaries.
No tool name, new threshold, numerical effect estimate, code patch or executable
configuration is invented. Expected effects are unverified aims.

Each frozen ImprovementCandidate has content-addressed ID/version, generator
version, Dataset binding, a logical pattern content reference and exact supporting
Sample references. It has authority ADVISORY, status PROPOSED and both
requires_offline_evaluation and requires_human_approval true.
APPROVED, PROMOTED and DEPLOYED are unsupported states.

## Determinism and snapshots

Sample, Feedback, Pattern and Candidate membership use canonical ID ordering.
Pattern and Candidate identities hash canonical content; created_at is metadata
outside logical identity. Candidate references bind logical pattern content,
excluding the pattern's creation timestamp. Equal immutable input and versions/config
therefore produce equal logical artifacts regardless of input order or wall clock.

Adding Feedback or rebuilding a Dataset does not update an existing Pattern or
Candidate. Explicit analysis/generation is required for a new Dataset ID.
Old artifacts continue to verify against their pinned Dataset; source corruption
causes fail-closed queries rather than silent relabeling.

## Persistence, queries and integrity

Apply the existing explicit migration chain to Dataset v8, then
migrate_candidates(database) for additive SQLite v8 → v9.
Only failure_patterns and improvement_candidates tables and their indexes are added.
Migration preserves earlier tables, rolls back on failure and rejects future schema.

BEGIN IMMEDIATE serializes independent-process proposals. Primary keys and
foreign keys constrain identity and parent bindings. Repeated generation returns the
stored canonical artifacts. An existing conflicting identity fails closed;
this is transactional idempotency, not an exactly-once guarantee.

ImprovementCandidateService exposes analyze(dataset_id), generate(dataset_id,
pattern_ids) and atomic propose(dataset_id). These are explicit offline operations.
ImprovementCandidateStore exposes get_pattern, list_patterns(dataset_id),
get_candidate and list_candidates(dataset_id).
Queries verify indexed bindings, checksums, logical IDs and deterministic rederivation
from pinned Dataset facts and generation rules. Forged support, cross-Dataset patterns
and mismatched Candidate/Pattern references fail closed.
Different analysis configurations can coexist; queries list stored artifacts in
canonical ID order, and each pattern retains its config.

Statistics provide pattern_count, candidate_count, candidate-type counts and per-pattern
support counts only. There is no ranking, priority, quality score, success probability
or automatic selection of a best candidate.

## Authority boundary and Phase 7-2

The service writes only the two advisory artifact tables. It calls no LLM,
ThreatAssessor, policy evaluator/mutator, human review/approval service, Tool,
Response Executor or runtime orchestrator. IncidentState, Evidence, Evaluation,
Feedback, Dataset, prompts, registries, models and configuration remain unchanged.
Runtime code does not import or automatically query these artifacts.

Phase 7-2 must implement explicit offline evaluation before any comparison or
promotion consideration. Approval, promotion, deployment, training, RAG and actual
prompt/strategy/policy/configuration mutation are outside Phase 7-1.
Checksums detect inconsistent tampering; they are not signatures against a privileged
attacker able to rewrite the entire database and all historical bindings.
