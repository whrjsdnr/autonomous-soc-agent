# Phase 3-7 — deterministic multi-model fusion

## Purpose and boundary

Fusion combines completed model inferences into an immutable, traceable analytical
artifact. It does not run models, extract features, train, calibrate, evaluate
operational detection performance, or select responses.

```text
SecurityRecord(s) -> existing FeatureExtractor -> FeatureSet
-> loaded packaged SecurityAI adapter -> SecurityAIResult -> AISignal
-> FusionInput(signal, original features) -> MultiModelFusionEngine -> FusionResult
```

**FusionResult is not Evidence, Observation, Hypothesis, ThreatAssessment or
IncidentState.** It has no severity, incident decision or execution authority.
Model agreement is not statistical confidence. Missing signals are not benign
evidence. IsolationForest scores are not attack probabilities.

## Input and trusted model bindings

`FusionInput` reuses the existing `AISignal` and original `FeatureSet`; signal/model
identity is not copied into another competing input contract. Supplying the original
features is necessary because the Phase 3-6 adapter explanation contains a fingerprint
and extraction provenance, but not the complete feature schema and values.

Trusted application setup loads packages using the existing pinned loader, then
calls `binding_from_package(package)`. The returned `FusionModelBinding` contains
only immutable manifest/profile metadata. The engine receives these bindings,
**never model objects, Registry, IncidentState or execution services**. No new model
loader or changes to Phase 3-6 packaging are needed. Bindings are an explicit allowlist
of package identities, including model name/version, schema/order/extractor, class
mapping, selected operating point, scaler/reference metadata and selection digest.

Validation rejects cross-incident mixing; mismatched model identity/task, package,
selection, schema, extractor or ordered features; invalid numeric features; and
signal/FeatureSet fingerprint or provenance mismatches. It also checks source record
contracts, unique valid source references, evidence reference consistency, observation
and inference timestamp order, class probability mapping/sum/argmax/confidence,
finite scores, frozen anomaly rank, both decisions and operating-point identity.

All inputs, including existing Pydantic instances, are detached and revalidated.
`model_copy`/`model_construct` do not bypass the engine boundary. No partial
FusionResult is returned on failure, and the engine retains no partially updated
cache. At most 128 inputs and 16 trusted package bindings are accepted per call.

These checks establish structural consistency, not authenticity of measurements or
proof that caller-created AISignals came from the claimed model. Use trusted
extractors/adapters and package pins. Fusion cannot verify an evidence store without
receiving one, and deliberately does not receive IncidentState. Existing upstream
extraction and `create_ai_signal` own their evidence-reference checks. A malicious
trusted Python caller can forge mutually consistent objects; Fusion is not a sandbox
or cryptographic inference attestation.

## Output and contributions

`FusionResult` contains:

- A deterministic SHA-256 `fusion_id` (also exposed as `fusion_fingerprint`), incident
  ID, fusion and compatibility versions.
- Unique original `signals`, preserving their source result IDs, payloads and times.
- One contribution per model/package/operating-point/logical-input identity; each
  contribution links all replay alias signal IDs. `deduplicated_signals` returns one
  representative per contribution. These are references, not new AISignal creation.
- `model_references`, retaining complete immutable package binding metadata.
- Correlation groups, agreement, confidence, explicit coverage entries and missing
  expected model kinds.
- A structured summary with contribution count, unique logical source record count,
  input group count, domains present and cross-domain linkage status; explicit
  limitations remain part of the result.

Each contribution preserves typed prediction scores, prediction/decision, exact
operating point, score semantics, feature fingerprint and full extraction provenance.
Its `model_reference` resolves to name/version, package manifest digest and selection
digest in the same result. No source identities are hidden by a single combined score.
Two models on the same flow produce two contributions but **one unique source record**.
An authentication window can contain many source event records. These counts are
lineage counts, not a claim of statistically independent observations.

## Model score semantics

XGBoost preserves `ClassificationPrediction`: predicted class, ordered class
probabilities and original model confidence. Class order is BENIGN, BruteForce,
DoS, PortScan. Fusion does not recalculate probabilities or temperature-scale them;
the packaged adapter has already applied its bound temperature (T=1 for Phase 3-5).

Both IsolationForest domains preserve `AnomalyPrediction`: raw negative
`score_samples`, raw anomaly measure, empirical-midrank normalized anomaly score,
legacy normalized threshold/decision and offset-relative decision score. A
contribution's separate operating point and `decision` preserve the adapter's
selected decision. These are ranking and threshold semantics, not attack probability.
No averaging, addition, voting probability or new calibration is implemented.

| Model | Selected raw operating point | Existing normalized threshold |
|---|---:|---:|
| Network IF | >= .4508608194824563 | .95 |
| Authentication IF | >= .5604416052073505 | .95 |

The two thresholds are never substituted for each other. Fingerprints, package
identity and selection digests remain bound to the actual Phase 3-6 metadata.

## Agreement and disagreement

`compatibility.py` is the single home of versioned interpretation rules. It is
**unrelated to PolicyEngine**, which governs permissions and execution.
Within one exact network correlation group:

| XGBoost | Network IF selected decision | Network relation | Agreement |
|---|---|---|---|
| Supported attack class | anomaly | attack_and_anomaly | consistent |
| BENIGN | anomaly | benign_with_anomaly | partial |
| Supported attack class | normal | attack_without_anomaly | partial |
| BENIGN | normal | no_alert | consistent |

`partial` preserves this cross-task disagreement: attribution and baseline deviation
are different tasks, so disagreement does not prove either model wrong. `no_alert`
means neither model alerted on that input; it does not establish safety. An attack
class plus anomaly is directional compatibility, not proof of compromise or two
independent observations.

`conflicting` means different versions/packages of the **same task** give incompatible
categorical predictions on the same correlated input. Different contents for one
identical model/package/input identity instead raise an identity collision.
Repeated same-task versions with identical predictions do not supply independent
corroboration. A singleton or pair without an applicable compatibility rule is
`insufficient`.

Global agreement preserves any local conflict. With multiple unrelated groups it
never claims global consistency: a comparable group plus an unrelated group yields
`partial`; only unrelated singleton groups yield `insufficient`. Per-group relations
remain available to downstream consumers, so this summary does not erase local detail.

## Confidence and coverage

Confidence is always **UNKNOWN**. There is no calibrated fusion confidence model and
no invented HIGH/MEDIUM/LOW or numerical risk score.

The caller must explicitly supply `expected_models` to the engine. This describes
coverage expectations, not required negative predictions. For a network-only task,
expect only the network model kinds. Coverage is `complete` when every expected kind
has a contribution, `partial` for multiple observed kinds with missing expectations,
`minimal` for one observed kind with missing expectations, or `none` with no signal.
A complete network-only result is still only network coverage.

Per-kind coverage distinguishes:

- `observed`: inspect contributions for the actual normal/anomalous/class decision.
- `not_reported`: no signal and no execution status was supplied; no execution claim.
- `not_run`, `failed`, `insufficient_input`: explicitly supplied immutable
  `ModelAvailability` entries with a reason.

Absence reasons do not generate signals, affect agreement, replace failed results
with normal, or increase confidence. Duplicate or contradictory observed/unavailable
statuses fail. Statuses are caller assertions for this call, not proof from an
execution log. Mixed success and failure for separate runs of the same kind must be
reported in separate calls; v1 intentionally does not guess run-level status routing.

## Correlation and provenance

A group requires the same incident, domain, feature fingerprint and **exact logical
source set**, including observation times and content digests. Logical source records
include source kind/name/version/record ID, record contract and provenance metadata.
Only newly allocated extraction record UUIDs are excluded from correlation identity.
Sources are canonically sorted; their original objects remain in signals/contributions.

This is exact-source correlation, not a time-distance clustering heuristic. Different
five-minute authentication windows remain distinct, even for the same account and
identical aggregate measurements. Equal measurements from offline and stream inputs
have equal feature fingerprints but distinct source provenance and separate groups.
Equal fingerprints alone never justify deduplication. Conflicting contents for one
logical source/observation time are rejected.

Network and authentication have no verified shared entity mapping in the current
contracts. They therefore remain separate groups even within one incident.
`summary.cross_domain_state` is `unverified` when both domains occur and
`not_applicable` otherwise. A caller cannot attach an arbitrary claimed account/IP
link to bypass validation. No same-attacker, campaign or account-takeover conclusion
is inferred. A future verified relation contract would require a separately reviewed
extension; v1 has no supported positive cross-domain link path.

## Duplicate/replay and deterministic identity

Exact duplicate signal IDs with identical content are removed. Conflicting payloads
for a signal ID or source result ID fail explicitly. A repeated inference with new
UUIDs but identical package/model/version/operating point, fingerprint and logical
sources becomes an alias of one contribution. Changed predictions under that same
identity are rejected, rather than silently picking one. Changing a model version
or package is a distinct contribution with an explicit model reference.

Signals sort by ID, contributions and groups by canonical digest. The fusion digest
uses fusion/compatibility version, incident, expectations, semantic contribution
identities and predictions, correlation groups and explicit coverage statuses.
It excludes generated signal/result/feature-set IDs and current execution timestamps.
Strict canonical JSON uses JSON arrays rather than Python tuples.

`[A,B,C]`, `[C,A,B]` and `[A,A,B,C]` produce the same complete result. New-ID replays
retain additional alias lineage in `signals`/`signal_ids`, but preserve fusion identity,
summary, agreement, confidence and coverage. The representative alias is chosen
canonically; it does not add analytical strength. `created_at` is a **source observation
watermark** (maximum contributing observation time, or None for empty input), not
wall-clock fusion execution time. Original inference timestamps remain in signals.

Deduplication is local to one call. The engine has no durable cross-call replay store.
Downstream code must not count repeated FusionResults with the same identity as
additional corroboration.

## Use and security boundary

```python
from soc_agent.security_ai.fusion import (
    FusionInput,
    ModelAvailability,
    MultiModelFusionEngine,
    binding_from_package,
)

# Packages were loaded by trusted setup; signals were produced upstream.
engine = MultiModelFusionEngine(
    bindings=(binding_from_package(classifier_package), binding_from_package(network_if_package)),
    expected_models=("network_classifier", "network_anomaly"),
)
result = engine.fuse(
    incident_id=incident_id,
    inputs=(FusionInput(signal=classifier_signal, features=original_network_features),),
    unavailable=(
        ModelAvailability(
            model_kind="network_anomaly",
            status="failed",
            reason="upstream inference failed",
        ),
    ),
)
```

Fusion performs no Registry registration, model fitting/inference, LLM call, evidence
creation, Observation/Hypothesis/ThreatAssessment creation, IncidentState or severity
change, Policy evaluation/change, Approval creation/change, Tool/Response execution,
IP blocking or account locking. Existing governance and packaging modules are
unchanged. Security tests install forbidden-call guards and compare populated state,
policy, approval manager, execution attempt state, Registry and input snapshots.

## Validation scope and Phase 4 handoff

Unit tests use explicitly synthetic typed adapter payloads for rule/failure cases.
Integration scenarios instead use the exact saved Phase 3-6 packages retained under
`tests/fixtures/security_ai_packages`, pinned by known manifest digests. They use the
existing loader/adapters and genuine SecurityRecord extraction and AISignal creation;
no new fitting, calibration or output manipulation occurs. Fixed probe measurements
were checked against actual predictions before assertions were written.

The scenarios cover BruteForce + anomaly, BENIGN + normal, BENIGN + anomaly,
authentication anomaly only, and both domains with unverified linkage. The
password-spraying-like signals in the cross-domain scenario do not establish that
one attack generated both inputs.

**Passing these tests validates architecture/contracts, not SOC detection efficacy.**
Fusion has not resolved Network IF's Phase 3-5 synthetic holdout **FPR .30**, nor
measured real-data false-positive performance. Small synthetic fixtures, shared
generator assumptions and lack of calibrated fusion confidence remain limitations.

Phase 4-1 now consumes FusionResult as model-derived context while retaining
its signal lineage, per-group disagreement, coverage gaps and limitations (see below).
Source Evidence remains separate. Incident decisions, severity application, response
planning and execution remain outside the fusion and assessment integration.

## Final verification (2026-09-22)

The resumed work preserved the initial Fusion implementation and fixed its strict
canonical-JSON tuple serialization failure. It added explicit expectations and
availability states, source/contribution summary, limitations, network relation
labels, validation/security tests and actual saved-package scenarios.

- Focused unit command: **76 passed in 6.60s**.
- Combined new unit/scenario command: **81 passed in 8.18s** (76 unit, 5 scenarios).
- Full regression: **1,298 passed in 306.67s**, exit code 0. The 1,217 existing tests
  were retained; no assertions were weakened.
- Ruff check, full format check, eight-module import smoke and diff check passed.
  The Markdown Python example was formatted after its initial format-check finding.
- No production detection metric, new fitting/calibration experiment, commit or push
  was performed. New scenarios reused the byte-identical Phase 3-6 package fixtures.

Workspace execution logs: `/tmp/soc-fusion-unit-final.log`,
`/tmp/soc-fusion-focused.log`, `/tmp/soc-fusion-full.log`. Temporary logs are not
required to run the checked-in fixture-based tests.

## Phase 4-1 assessment integration

The optional `ThreatAssessor.assess(state, fusion_result=fusion)` boundary now
revalidates retained results through shared fusion signal/aggregation rules and
passes their analytical information as untrusted model-derived context.
`FusionAssessmentResult.model_derived_context` retains the complete artifact
separately from `ThreatAssessment` and Evidence. Fusion-aware calls return an
unchanged IncidentState and reject new Observation/Hypothesis drafts; legacy
calls without fusion retain their existing state-snapshot behavior.

See [Fusion-aware threat assessment](fusion-aware-assessment.md) for Evidence
membership checks, prompt projection, resource limits, failure semantics and the
Phase 4-2 handoff. Retained lineage validation does not authenticate model execution
or recompute absent FeatureSet values. Phase 4-2 decisions and response actions
are not implemented by this integration.
