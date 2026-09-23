# Phase 4-2: Human-governed incident decision

`IncidentDecisionEngine` consumes completed analysis and produces an immutable
review artifact. It does not infer new facts, run an LLM, extract features, invoke
models, plan responses, or change incident state. This is an analytical decision,
not an execution command or approval.

## Existing contracts and API

`IncidentState` owns Evidence, Observations and Hypotheses, incident status and
severity. Its validated append methods produce new snapshots. `ThreatAssessment`
is advisory: it contains identity, incident, severity, confidence, summary,
Evidence/Observation/Hypothesis references and creation time. It does not contain
a structured attack-confirmation field, negative finding, or source snapshot version.

`AssessmentResult` validates assessment references against a state snapshot.
Legacy `ThreatAssessor` returns new observations/hypotheses in its returned state;
use that returned state for the decision. `FusionAssessmentResult` also retains
`model_derived_context: FusionResult`. Fusion-aware assessment returns unchanged
state and no new observations/hypotheses.

```python
from soc_agent.decision import IncidentDecisionEngine

# Existing evidence-based path: no model context required.
decision = IncidentDecisionEngine().decide(result.incident_state, result.threat_assessment)

# Fusion-aware path: pass the complete FusionAssessmentResult envelope.
decision = IncidentDecisionEngine().decide(
    fusion_result.incident_state,
    fusion_result.threat_assessment,
    fusion_assessment=fusion_result,
)
```

The optional argument is a `FusionAssessmentResult`, not a bare `FusionResult`.
This prevents accidentally pairing an unrelated assessment with a fusion artifact.
The engine revalidates nested dictionaries using existing `AssessmentResult` and
`FusionAssessmentResult` contracts. These reuse IncidentState membership checks,
`validate_assessment_fusion` and the original retained-Fusion reconstruction
validator. Contribution, signal, provenance, package metadata, coverage, correlation
and fusion identity checks are not reimplemented in the decision layer.

The envelope must contain the supplied assessment and state with identical
contents, allowing irrelevant reference/record ordering. Different envelope state
contents are rejected even if their incident IDs agree. For the legacy path,
reference membership in the supplied state is sufficient; newer snapshots with
additional evidence are accepted. Additional unreferenced evidence is not silently
used as support. Neither path proves the assessment was generated at the same
instant as the state: **no source snapshot/version binding exists upstream**.
Timestamps do not prove that binding. This limitation is always returned.

## Output and evidence separation

The frozen `IncidentDecision` uses tuples and existing frozen nested models:

- SHA-256 `decision_id`, `decision_version=1.0.0`, incident and rule version.
- A separate `outcome`, applied rule codes, rationale and uncertainties.
- The retained assessment, including its ID, advisory severity/confidence and prose.
- Canonically ordered source Evidence IDs, linked observations and hypotheses.
- The complete original validated FusionResult, or `None`, in `model_derived_context`.
- Additional investigation flag and reasons, human review reasons and limitations.

The Evidence ID set is the union of assessment and linked interpretation support.
Model source references remain in the model context; no model identifier is promoted
to source Evidence. Fusion IDs, AISignal IDs, contribution IDs, feature fingerprints,
package hashes, predictions and anomaly scores remain model lineage. Observations
and hypotheses stay in separate fields. The original assessment summary is retained
as untrusted advisory text, not parsed into new facts. Reference validation does not
establish that this text is semantically entailed by its cited Evidence.

## Rules: `incident-decision:v1`

Rules live in `decision/rules.py`; these are review-routing rules, not PolicyEngine
execution permission rules. No probabilities, risk scores or new thresholds exist.
The existing enum distinction INFO versus non-INFO is used as an **advisory concern
indicator**, not as attack proof or a new incident severity assignment. In fusion
mode that concern may itself have been influenced by models; the engine does not
claim it is independent Evidence corroboration.

Ordered outcome precedence:

| Condition | Outcome | Meaning |
| --- | --- | --- |
| Assessment severity is non-INFO | `suspicion_for_review` | Review advisory concern; no confirmed compromise |
| Otherwise any classifier non-BENIGN or anomaly contribution | `further_investigation` | Model indication requires source verification |
| Otherwise follow-up reasons exist | `insufficient_basis` | Inputs do not support ending review |
| Otherwise | `no_additional_alert_basis` | No additional alert indicator in these inputs; not safety |

All applicable reasons survive outcome precedence:

- Non-INFO assessment requires checking its interpretation against Evidence.
- No linked observation/hypothesis requires inspection of the source Evidence.
- Any model alert requires collection or verification of supporting Evidence.
- Each `not_reported`, `not_run`, `failed`, `insufficient_input` coverage entry
  remains distinct, including its upstream reason in the retained context.
- BENIGN plus anomaly requires separate review; there is no averaging or cancellation.
- Unverified network/authentication linkage requires separate groups; no shared
  actor, account, attack, causal chain or successful compromise is inferred.
- Differing advisory-concern and model-alert indicators request review of both.
  This is an explicit coarse indicator comparison, not semantic comparison of prose.
- No model alert means only no alert in supplied contributions. Missing coverage
  remains a follow-up reason. Absent fusion is recorded as `fusion_not_supplied`,
  without requiring optional models on the legacy path.

Attack success, account takeover and damage have no automatic confirmed outcome.
Every output includes uncertainty and a human review reason. An additional
investigation flag describes analytical need and never starts an investigation.

## Severity, confidence and governance

The original assessment's severity and confidence remain nested with their source
assessment identity. They are not integrated decision scores and never update
`IncidentState`. Fusion confidence remains UNKNOWN. Agreement, anomaly rank and
class probabilities are not converted to decision confidence.

The engine has no injected execution, registry, approval, policy or LLM services.
It does not add Evidence, change status/severity, register models/tools, block IPs,
lock accounts or return an ActionProposal. Existing PolicyEngine still evaluates
permissions/risk, ApprovalManager still records explicit human decisions, and
GovernedExecutor still rechecks policy and exact action/approval binding before
execution. These modules and packaging contracts were not modified.

## Determinism and failure

SHA-256 uses the existing canonical JSON utility over the decision payload excluding
`decision_id` and nested `created_at` clocks. The engine generates no wall-clock
timestamp or random UUID. Upstream reference identities are retained: a separately
created assessment with another ID is a different referenced analysis, not an alias.
This is a retained-analysis identity, not an authentication signature or proof of
unchanged historical Evidence. No persistent deduplication service is introduced.

Evidence/observation/hypothesis reference ordering is normalized. Fusion uses its
existing required canonical representation, preserving the original validated
artifact, including alias lineage; it is not re-fused with a new interpretation.
Same inputs and rules produce identical complete results. Creation-clock-only
changes do not change the decision ID. Content or upstream identity changes can.

Invalid input propagates existing Pydantic/assessment errors or a ValueError for
mismatched envelopes. There are no retries, partial decisions, safe fallback
classifications, or caller-object mutations. As elsewhere in this repository,
Pydantic `model_copy`/`model_construct` are not trust boundaries. The engine performs
the validation; consumers must not accept an untrusted constructed output as an
authorization token. A decision hash is not proof of trusted model execution.

## Tests and limitations

New units cover legacy inputs, immutable results, canonical ordering/stable identity,
interpretation separation, model alerts/disagreement, all missing coverage statuses,
invalid incidents/references/identities, changed envelopes and fusion lineage,
forbidden service calls and unchanged inputs on success/failure.

Seven integration scenarios use synthetic SecurityRecords, existing feature
extractors, actual pinned saved Phase 3-6 packages, genuine adapter outputs/AISignals,
Phase 3-7 fusion and Phase 4-1 assessment. **Only the LLM is mocked.** No prediction
is edited and no model is trained. Cases: BruteForce plus anomaly, BENIGN plus
anomaly, authentication anomaly, unverified network/authentication groups, upstream
failure/missing coverage, legacy evidence path, and BENIGN plus normal. Failure
availability is explicitly caller-reported, not a simulated normal prediction.

Synthetic contract checks do not establish real-world SOC efficacy, LLM quality,
calibrated confidence or source authenticity. Phase 3-5 network anomaly synthetic
holdout FPR 0.30 remains unresolved. Retained Fusion lacks original feature values
and executable model provenance proof; its shared validator checks internal lineage,
not authenticity against a malicious producer capable of coherent fabrication.

## Next phase handoff

A future human review consumer can display outcome, advisory assessment, source
references, separate model groups, uncertainties and follow-up reasons. Any future
state transition, response planning or execution requires a separately designed
and tested governance path. This phase provides none of those capabilities.

## Verified results (2026-09-22)

- New unit tests: **30 passed**; real-package/Mock LLM scenarios: **7 passed**.
- Final combined focused run: **37 passed in 5.04s**, exit code 0
  (`/tmp/soc-phase42-focused.log`).
- Final full `uv run --offline pytest -v`: **1,388 passed in 288.36s**, exit code 0
  (`/tmp/soc-phase42-full-final.log`), versus the Phase 4-1 baseline of 1,351.
- Earlier full run before the last three units were added: 1,385 passed in 305.85s,
  exit code 0 (`/tmp/soc-phase42-full.log`). The final run supersedes it.
- Full Ruff check and format check passed, including the Markdown Python example.
- Git diff whitespace check and explicit whitespace checks of all seven new files
  passed. Existing untracked `tests/fusion_support.py` was preserved unchanged.
- No existing tests were removed or weakened, no dependency was added, and no
  commit or push was performed. Temporary logs are not required to reproduce tests.
