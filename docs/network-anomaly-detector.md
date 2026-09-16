# Phase 3-3: Independent network anomaly detection

## Purpose and shared contract

XGBoost asks which known training class resembles the input. IsolationForest asks
how unusual it is relative to a learned benign reference population. An unusual
flow is not necessarily malicious; this model neither predicts an attack class
nor guarantees detection of unknown/zero-day attacks.

```text
                    Network FeatureSet
                     /            \
                    /              \
                   v                v
       XGBoost Classifier    IsolationForest
          supervised          unsupervised
                   |                |
          attack prediction   anomaly prediction
                    \              /
                     \            /
                      v          v
                   future Phase 3-7
                    Evidence Fusion
                          |
                       SOC Agent
```

The existing `CICIDS2017Adapter`, `NetworkFeatureExtractor`, and
`network_attack_features@1.0.0` are reused unchanged. Features remain
`duration_us`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes` in that order.
The `network_flow@1.0.0` extractor, units, byte accounting, and direction convention
must match in offline and runtime sources. There is no anomaly-specific parser,
feature schema, or flow aggregator.

The existing ordered float32 projection moved to `preprocessing.py` and is shared
by both models; the old `classifier.feature_matrix` import remains available.
Schema name/version/complete definitions/order and extractor identity are checked.
Missing features, negative values, nonpositive duration, NaN and Infinity fail
closed; no runtime imputation or zero-fill occurs.

## Training population and scaling

**Training labels may select the benign reference population, but labels are never
part of the model input.**

`train_anomaly(dataset, config=AnomalyTrainingConfig(...))` uses the existing seeded
grouped train/validation/test split first. Only exact `BENIGN` rows in the train
partition fit StandardScaler, IsolationForest, and score normalization. Labels are
also used for split stratification and held-out binary evaluation, never supplied
as `y` to IsolationForest.fit. At least two distinct benign training inputs are
required; missing/insufficient benign reference data fails rather than training
on attacks. The existing five-independent-groups-per-class split precondition
remains in force, with no random-split fallback or silent class removal.

StandardScaler fits mean/variance/scale on the benign training population only.
Validation/test statistics are not consulted. Its parameters and sample count are
immutable `ScalerState`. Runtime applies `(ordered_input - mean) / scale` in float64,
matching StandardScaler's two operations, and checks representability for the
forest's internal float32 input. Constant columns use sklearn's scale=1 convention.

Axis-aligned isolation trees are largely invariant to positive affine rescaling;
standardization here makes preprocessing explicit and numerically consistent.
It is not evidence of improved detection or a reason to fit on held-out data.
Scaler fitting never happens at runtime.

## Model configuration and score semantics

Default `network_anomaly_iforest@1.0.0` configuration:

- 64 trees, max_samples=min(256, benign training count), all five features.
- random_state=42, n_jobs=1, bootstrap=False, warm_start=False.
- contamination=`auto`; no estimate of production anomaly prevalence is asserted.
- Canonical decision threshold: normalized anomaly_score >= 0.95.

The installed scikit-learn implementation was inspected directly:

- `score_samples(X)` is lower for more abnormal samples.
- `decision_function(X) = score_samples(X) - offset_`.
- sklearn's `predict` returns -1 for negative decision_function, +1 otherwise.
- With contamination=`auto`, the current implementation uses offset_=-0.5.

`NetworkAnomalyPrediction` preserves all relevant meanings:

| Field | Meaning |
| --- | --- |
| raw_score | sklearn score_samples; lower means more unusual |
| raw_decision_score | raw_score minus the fitted sklearn offset |
| raw_anomaly_measure | negative raw_score; larger means more unusual |
| anomaly_score | empirical mid-rank relative to fixed benign training scores |
| threshold | fixed application configuration, default 0.95 |
| is_anomaly | anomaly_score >= threshold |

The canonical boolean does not use sklearn's default zero decision threshold and
can disagree with sklearn.predict. Neither value is an attack attribution.
The wrapper does not expose an attack class or a calibrated confidence field.

### Fixed normalization

After fitting, compute `r_i = -model.score_samples(scaled_benign_train_i)`, sort the
finite reference values, and freeze them in `AnomalyScoreReference`. For runtime
measure `r`, compute:

```text
L = number of reference values strictly less than r
U = number of reference values less than or equal to r
anomaly_score = (L + U) / (2 * number_of_reference_values)
```

This empirical mid-rank gives tied values equal scores. Below the reference minimum
maps to 0; above its maximum maps to 1. A median reference value is approximately
0.5, not a 50% attack probability. The result is bounded and monotonic in raw anomaly
measure; it is not a calibrated probability. Equal raw scores always have equal
normalized scores. No event or batch updates the reference, extrema, scaler, or
threshold. Runtime offers only per-FeatureSet prediction, with no fit/update API.

The threshold 0.95 is an explicit baseline choice, not a validation-selected,
optimal, calibrated, or production-ready threshold. `auto` contamination affects
the sklearn offset, not this percentile decision. In-sample reference scores,
finite-sample ranks, ties, and saturation outside observed ranges all affect its
meaning. Threshold/normalization evaluation belongs to Phase 3-5; no search or
recalibration is performed here.

## Evaluation

Validation and test include benign and attack fixture rows. Truth is binary:
BENIGN=false, any other label=true. Evaluation records anomaly precision, recall,
F1, confusion matrix `[[TN, FP], [FN, TP]]`, and class supports. Zero-division is
explicitly zero. ROC-AUC and average precision use raw_anomaly_measure to retain
ranking beyond percentile saturation. Average precision is the step-integral PR
summary, not trapezoidal PR-AUC. Both AUC summaries are undefined (`None`) for a
single-class evaluation population.

Accuracy alone would obscure minority anomaly failures, so it is not the primary
anomaly report. These metrics use labels only for evaluation. They neither
optimize thresholds nor initiate additional investigation.

## In-memory artifact strategy and security

This phase deliberately chooses the allowed in-memory strategy:

```text
AnomalyTrainingResult
  detector: NetworkAnomalyDetector (fitted sklearn model, detached private copy)
  metadata: AnomalyTrainingMetadata (immutable, JSON-round-trippable contract)
```

The immutable `AnomalyInferenceProfile` binds the shared schema/extractor, model
identity/configuration, fitted scaler parameters, fitted max_samples, sorted
reference scores, sklearn offset, and threshold. Metadata also retains source
file digests, dataset identity, existing split metadata, baseline row indices,
invalid-row policy, evaluation, and Python/numpy/sklearn versions. Detector/profile
consistency and population dimensions are validated. Profiles and predictions are
frozen; predict accepts no threshold override. Caller-owned fitted objects are
copied before being retained.

Serialization choices considered:

| Choice | Decision |
| --- | --- |
| pickle/joblib | No loader: arbitrary Python object loading weakens the boundary |
| skops | New dependency and trust policy; deferred |
| ONNX | Conversion/runtime dependencies and parity work; deferred |
| custom forest JSON | Versioned tree format and scoring parity burden; deferred |
| in-memory model + typed profile/metadata | Implemented without new dependencies |

No anomaly model save/load API, persisted model digest, or arbitrary-object loader
is provided. JSON metadata alone cannot reconstruct a fitted forest. Persistence
and cryptographic/integrity binding of model/scaler/reference/threshold are future
packaging work. Existing XGBoost native artifact integrity is unchanged.

Frozen snapshots and private copies protect ordinary accidental mutation, not
malicious trusted Python modifying private sklearn internals. Profile validation
is not proof that an independently supplied fitted forest was trained on the
claimed rows. Use the trusted training factory; no signed attestation is claimed.

## Offline → streaming and integration boundaries

```text
Kernel/eBPF → Network Telemetry → Security Data Bus → Source Adapter
    → NetworkFeatureExtractor → FeatureSet
                                  |-- XGBoost
                                  `-- IsolationForest
```

The same measurements from a DATASET record and a STREAM record have identical
input fingerprints and identical raw/normalized anomaly scores and decisions,
while retaining distinct provenance. The scenario also passes that same FeatureSet
to XGBoost separately; outputs are never combined. No component decides which model
is right when outputs disagree. Future Phase 3-7 may consume both with provenance
and uncertainty for governed reasoning, without promoting predictions to facts.

Phase 3-6 can wrap the detector in a SecurityAI handler and return an anomaly label
plus raw/normalized scores. Percentiles must not be relabeled as calibrated
confidence. FeatureSet/result binding, trusted packaging, runtime resource limits,
and explicit registry registration belong there. No AISignal, Evidence,
Observation, policy decision, approval, response, Agent call, or state mutation is
created by this phase. eBPF, data buses, autonomous investigation, fusion,
retraining and self-improvement are not implemented.

## Usage

```python
from soc_agent.security_ai.network import AnomalyTrainingConfig
from soc_agent.security_ai.network.anomaly_training import train_anomaly

result = train_anomaly(dataset, config=AnomalyTrainingConfig(n_estimators=64))
prediction = result.detector.predict(feature_set)
metadata_json = result.metadata.model_dump_json()  # Metadata only, not a model file.
```

## Fixture measurements and limitations

Actual CIC-IDS2017 available: **NO**. No download was performed.
**NO REAL CIC-IDS2017 METRICS AVAILABLE.**

The end-to-end synthetic fixture has 120 rows / four artificial classes, split
72 train / 24 validation / 24 test. Only 18 benign train rows fit the scaler,
16-tree forest, and normalization. Seed=42 and threshold=0.95 are fixed.

| Metric | Synthetic pipeline-test value |
| --- | --- |
| Anomaly precision | 0.0 |
| Anomaly recall | 0.0 |
| Anomaly F1 | 0.0 |
| ROC-AUC (raw anomaly measure) | 0.75 |
| Average precision (PR summary, raw measure) | 0.90 |
| Confusion matrix | [[5, 1], [18, 0]] |

All 18 attack fixture test rows were missed at this threshold. The nonzero ranking
metrics do not rescue the failed binary operating point. No threshold or fixture
was changed to improve these numbers. This demonstrates why contract correctness
is separate from useful detection and why Phase 3-5 evaluation is required.
Tests assert mechanics and independently known metric calculations, not these
measured values as performance targets.

Small benign populations, tied percentile ranks, isolation-tree tail saturation,
baseline representativeness, and distribution shift limit the score. Whole-corpus
throughput/memory and actual telemetry parity remain unmeasured. Nothing here
establishes zero-day detection capability, real IDS performance, or calibration.
