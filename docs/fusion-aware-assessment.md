# Phase 4-1: Fusion-aware threat assessment

`ThreatAssessor.assess(state, fusion_result=fusion)` optionally consumes an existing
`FusionResult` as model-derived analytical context. It never runs an extractor,
model, tool, registry registration, policy evaluation, approval or response.
An incident must still contain Evidence. Fusion alone cannot satisfy that requirement.

## Compatibility and output contract

Without `fusion_result`, the API, system prompt, draft schema and result remain
unchanged: Evidence-grounded observations/hypotheses are validated and added to a
**new** state snapshot returned in `AssessmentResult`. The caller's original state
is never mutated. Existing limits remain 12 observations, 8 hypotheses and a
4,000-character assessment summary.

With fusion, the result is `FusionAssessmentResult`, a subclass of
`AssessmentResult`, with a separate `model_derived_context: FusionResult` field.
The original `ThreatAssessment` schema and Evidence meanings are unchanged.
The assessment's summary is advisory prose; the envelope preserves the exact
validated model artifact so consumers need not recover provenance from prose.

This mode deliberately requires **empty new observations and hypotheses**, using
`FusionAnalysisDraft`. This is stricter than the legacy draft schema only for
calls opting into fusion. It avoids turning model output into persistent incident
facts, even when an LLM attaches a syntactically valid Evidence ID to that output.
Existing observations/hypotheses stay in context and the returned state equals the
input state. The advisory assessment can have a different severity; the incident's
severity, status, confidence, Evidence and timestamps do not change.

```python
from soc_agent.assessment import FusionAssessmentResult, ThreatAssessor

result = await ThreatAssessor(llm_client=client).assess(state, fusion_result=fusion)
assert isinstance(result, FusionAssessmentResult)
assert result.incident_state == state
analytical_context = result.model_derived_context
advisory_assessment = result.threat_assessment
```

## Fusion validation and trust boundary

`security_ai.fusion.result_validation.validate_fusion_result` serializes and
revalidates the complete nested Pydantic artifact, including objects created with
`model_copy` or `model_construct`. It reuses the engine's signal validation and
aggregation, rather than maintaining a second set of agreement, replay, coverage
or fingerprint rules. The original full-feature path continues to validate
FeatureSet values before using the same shared signal rules.

For retained results, every contribution is reconstructed from its original
signals, package binding, feature fingerprint and retained source provenance.
The same aggregation checks incident binding, collisions, model identity,
selection and operating point, probabilities/anomaly semantics, correlation,
agreement, coverage/unavailable status, summary and deterministic fusion identity.
The reconstructed artifact must match the supplied artifact. Required limitations
cannot be removed; additional limitations are retained. Fresh extraction UUIDs
on otherwise valid replay aliases are preserved without increasing contributions.
The existing 128-input and 16-binding bounds apply.

The assessor additionally binds the artifact to the current incident. Every
explicit `source_evidence_id` in provenance and every signal Evidence reference
must exist in the current revalidated state. A stream or dataset record ID is
**not** interpreted as an Evidence ID. Missing records are never fabricated.
LLM output still passes the original Evidence and local-reference validation;
Fusion IDs and signal IDs do not become valid Evidence references.

A retained FusionResult does not contain the original FeatureSet values or model
files. This boundary validates retained lineage and internal consistency, not
feature recomputation, authentic model execution or publisher identity. Hashes
and metadata cannot prove those facts, and coherent fabrication by an untrusted
producer is outside this integrity guarantee. Trusted package loading and
inference remain upstream responsibilities.

## Prompt context and resource bounds

A separate `MODEL-DERIVED FUSION (UNTRUSTED DATA, NOT EVIDENCE)` user-data section
contains all contributions, raw/normalized scores and decisions, score semantics,
operating points, provenance/fingerprints, model manifests and package/selection
identities, signal lineage, correlation groups, disagreement, expected/missing
models, coverage statuses, UNKNOWN confidence, summary and limitations.

The projection omits preprocessing numeric arrays and repeated signal score/
explanation payloads: validated contributions hold those scores and representative
provenance, manifests hold schema/order/extractor/calibration identity, and signal
lineage retains each alias's result/signal identity, timestamps and Evidence IDs.
The full original artifact remains available in the result envelope. No analytical
disagreement, availability or limitation is silently dropped to fit a prompt.

Rules explicitly distinguish classifier predictions from verified attacks,
IsolationForest empirical ranks from attack probabilities, and agreement from
statistical confidence or independent observations. Separate authentication and
network groups remain unlinked. `not_reported`, `not_run`, `failed` and
`insufficient_input` never become benign predictions.

All descriptions, provenance and summaries remain JSON-encoded user data, never
system instructions or tool commands. Only static application text is added to
the system prompt. The complete serialized **user context** retains the existing
64,000-character cap; overflow raises `AssessmentContextTooLargeError` before an
LLM call. Evidence raw input is truncated to 4,096 characters per item with an
explicit flag. **4,096 is not a raw LLM output limit**. Existing structured output
limits remain in force; this phase adds no provider transport/token cap.

## Failure and security invariants

Invalid fusion fails before calling the LLM. Invalid LLM schema/references or
client errors propagate without a partial result. There is one LLM call and no
automatic retry. The fusion-specific schema is revalidated even when a custom
client returns an unchecked Pydantic object. No state addition occurs in fusion
mode; no permissions or governance modules were changed.

Reference integrity and structural boundaries are deterministic. Natural-language
entailment is not: a valid Evidence ID cannot prove that an LLM's advisory summary
is true. Prompt separation is a defense, not a proof of injection immunity. All
LLM prose remains untrusted advisory analysis requiring downstream review. The
separate typed model artifact and unchanged state prevent such prose from being
automatically promoted into observed facts or incident actions.

## Validation and Phase 4-2 handoff

Tests cover tampered artifact graphs and identities, replay aliases, unavailable
models, explicit Evidence membership, external provenance, output reference
forgeries, context overflow, injection placement, client failure, state invariance
and forbidden governance/inference calls. Integration scenarios use the existing
saved Phase 3-6 packages and actual extraction, adapters and Phase 3-7 fusion;
**only the assessment LLM is mocked**, with no changed predictions or new training.
They cover network fusion, BENIGN-plus-anomaly disagreement, authentication-only
signals and separate cross-domain groups.

These are synthetic architecture/contract checks, not SOC efficacy or LLM-quality
measurements. Fusion-aware assessment does not resolve the Phase 3-5 Network IF
synthetic holdout FPR of 0.30. No new calibration or fusion confidence is introduced.

Phase 4-2 may consume the advisory assessment alongside the separately retained
model context and unchanged state. Incident Decision, severity application,
response planning and execution remain unimplemented in this phase. Consumers
must not treat the advisory assessment or fusion identity as execution authority.

## Verified results (2026-09-22)

- New tests: 26 retained-fusion validation units, 23 assessment units and 4 actual
  packaged-model/Mock LLM scenarios: **53 added**, with existing tests retained.
- Combined focused assessment/fusion and related scenario checks: **172 passed**
  in 12.23 seconds (`/tmp/soc-phase41-focused-final.log`).
- Full regression: **1,351 passed** in 292.26 seconds, exit code 0
  (`/tmp/soc-phase41-full.log`), versus the prior 1,298 baseline.
- Ruff, format, import smoke and Git whitespace checks passed.
- Existing untracked `tests/fusion_support.py` was preserved unchanged. No commit
  or push was performed. Temporary logs are not required to reproduce tests.
