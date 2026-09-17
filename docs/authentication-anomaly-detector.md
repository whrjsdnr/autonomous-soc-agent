# Authentication / account behavior anomaly detector

Phase 3-4 adds an independent, in-memory IsolationForest baseline. No real
enterprise authentication dataset is available in this repository. All reported
results below are **synthetic pipeline-test metrics**, not security performance.
No data is downloaded and no new dependency is required.

## Events, adapters, and finite windows

`AuthenticationEvent` requires `event_id`, timezone-aware `event_time`,
`account_id`, `authentication_result` (`success` or `failure` only), and
`source_identifier`. Unknown results, naive timestamps, empty identifiers, and
extra fields are rejected. Success/failure are observed event attributes;
the detector's anomaly decision is an inference, not an observed attack.

`authentication_record` adapts a typed event and a DATASET or STREAM
`SourceReference` into an `authentication_event@1.0.0` `SecurityRecord`.
This adapter performs no file or network I/O. Evaluation labels are external to
these event records. Existing Evidence can instead be resolved by
`record_from_evidence`; extraction requires the matching IncidentState and checks
actual source content, identity, and timestamp. Raw events are never promoted to
Evidence automatically.

`AuthenticationWindowExtractor.extract(records)` consumes a **finite, complete
batch**. Times are normalized to UTC. Windows are epoch-aligned, exactly 300
seconds long, and half-open `[start, end)`. An event at 10:05:00 belongs to the
10:05 window, not the 10:00 window. Each account is aggregated separately.
Accounts must be consistently namespaced by upstream adapters across tenants.

Events are sorted by event time then event ID, and windows by account then start.
Duplicate event IDs (even identical copies), internal record IDs, and logical
source references are rejected before aggregation, including duplicates across
accounts. Event IDs must be globally unique within the supplied batch. Empty
batches return an empty tuple; empty windows are not synthesized. Late arrivals
can be included by recomputing a complete finite batch; existing snapshots are
not modified. There is no live consumer, watermark, incremental merge, or
cross-call deduplication service. Partial windows must not be represented as
complete by the caller.

## Versioned feature contract

Schema: `authentication_behavior_features@1.0.0`.
Extractor: `authentication_window@1.0.0` (fixed five-minute semantics).
The schema defines this exact order:

| Feature | Type | Formula / unit |
|---|---|---|
| failed_login_count | int | Number of failures |
| successful_login_count | int | Number of successes |
| total_login_count | int | failures + successes |
| failure_rate | float | failures / total |
| login_attempt_rate | float | total / 300 seconds |

Only nonempty windows reach feature creation, so division by zero is impossible.
Runtime validation additionally checks nonnegative counts, positive total,
exact arithmetic consistency, finite values, and representability as float32.
Missing/extra features, schema name/version/order changes, and extractor changes
fail closed. There is no imputation or silent feature reordering.

Account IDs, source identifiers/IPs, event IDs, timestamps, labels, and future
windows are not features. Counts and rates capture behavior without allowing the
model to memorize identity. A single event does not describe a frequency or
failure pattern; the account window does. This contract is distinct from both
the network flow contract and the older Phase 3-1 authentication-summary fixture.
Changing window semantics requires a versioned contract change.

## Provenance and offline / streaming compatibility

Each FeatureSet retains one existing FeatureSourceReference per actual event,
including logical source identity, source record ID, observed time, and canonical
content digest. The window sidecar retains account, bounds, and aligned event
IDs for grouping. FeatureSet UUID and creation time are application metadata.

Input fingerprint includes schema/extractor identity and ordered feature values;
it excludes source identity, account identity, UUID, and creation time. Therefore
the same measurements from different accounts or DATASET/STREAM sources have the
same fingerprint and prediction but distinct provenance. Source identifiers and
account identifiers remain sensitive provenance/context; they are not magically
anonymized by excluding them from model inputs.

Provenance proves references to the supplied records, not authenticity of an
external log producer. Concrete extraction performs the calculations; standalone
Python snapshot construction cannot prove an arbitrary caller computed them
correctly.

## Split first, then normal-only fit

`AuthenticationExample` combines a window with an explicit `normal`/`anomalous`
evaluation label. Unknown/missing labels are rejected. The evaluation training
entry point requires both classes; it does not silently treat unlabeled data as
normal. Labels select the normal training baseline and support stratification
and evaluation. They never enter a FeatureSet or the `y` argument of fitting.

The existing grouped splitting algorithm is shared in `security_ai/splitting.py`:
union windows from the same account and windows with identical input fingerprints.
Conflicting labels for identical inputs are rejected. Duplicate original events
or source records across windows are rejected. All partitions remain disjoint
by account, event, and feature fingerprint. Require at least five independent
connected groups per class. StratifiedGroupKFold with seed 42 assigns fold 0 to
test, fold 1 to validation, and folds 2–4 to train. Every partition must contain
both labels or the split fails; there is no random fallback.

Only normal **training** windows fit StandardScaler and IsolationForest. Validation
and test never fit scaler parameters, score references, or thresholds. Account
grouping avoids adjacent windows of one account crossing partitions. This is an
unseen-account evaluation, not a chronological deployment evaluation; shared
infrastructure/time correlations can remain. Identical fingerprints with different
labels indicate insufficient feature discrimination and intentionally prevent
this baseline split. Small/connected datasets can be unsuitable for this policy.

## Model and score semantics

Default: `authentication_anomaly_iforest@1.0.0`, 64 trees, max_samples up to 256,
seed 42, CPU `n_jobs=1`, `contamination="auto"`, no tuning. StandardScaler is an
explicit reproducible preprocessing convention, not a claim that IsolationForest
requires normalization for correctness. Its frozen means/scales/variances are
reused at runtime, including scale=1 for constant columns.

- `raw_score`: sklearn `score_samples`, lower is more unusual.
- `raw_anomaly_measure`: `-raw_score`, higher is more unusual.
- `raw_decision_score`: `raw_score - sklearn offset_`.
- `anomaly_score`: fixed empirical mid-rank relative to normal training scores.

For a new raw measure x, let L be the number of reference measures strictly less
than x and U the number less than or equal to x. Score = `(L + U) / (2*N)`.
Ties receive their mid-rank; extreme values saturate at 0 or 1. Normalization is
fixed at training, never recomputed from runtime batch composition. Shared scaler,
normalization and binary evaluation preserve network-model behavior and imports.

`is_anomaly = anomaly_score >= 0.95`. This explicit baseline threshold is neither
optimal nor calibrated. Contamination `auto` determines sklearn's offset (normally
-0.5), not a claimed production anomaly prevalence. The percentile decision can
differ from sklearn's `predict`. Anomaly score is **not attack probability,
calibrated confidence, account takeover attribution, or password-spraying proof**.
Prediction includes the feature fingerprint and immutable behavior values for
inspection, e.g. failed count and failure rate, without attack-type claims.

## Metadata / artifact security

Model/schema/extractor identities, exact feature order, configuration, scaler
parameters, training score distribution, threshold, split membership, baseline
indices, evaluation and library versions are immutable typed metadata. Detector
construction checks bindings and detaches the fitted forest by copying it.

Persistence remains deferred, as in Phase 3-3. No pickle/joblib loader is exposed;
metadata alone cannot reconstruct the forest. The in-memory Python estimator is
trusted code, not tamper-proof storage or a signed artifact. Existing XGBoost
native artifacts are unchanged.

## Synthetic scenario results

`tests/scenarios/test_authentication_anomaly_detector.py` generates 15 accounts,
30 windows (normal and anomalous per account), 750 events, with labels assigned
externally to event generation. For the scenario only, 16 trees are used.
18/6/6 windows enter train/validation/test. Nine normal train windows fit the
scaler and forest. Test has three normal and three anomalous windows.

| Test metric | Synthetic result |
|---|---:|
| Precision | 0.75 |
| Recall | 1.0 |
| F1 | 0.8571428571 |
| ROC-AUC (raw anomaly measure) | 0.6666666667 |
| Average Precision (raw anomaly measure) | 0.75 |

Confusion matrix (normal, anomaly): `[[2, 1], [0, 3]]`. These tiny fixture metrics
validate mechanics only. Threshold metrics and ranking metrics measure different
properties; no tuning was performed to improve either. Actual authentication
attack detection performance is **not measured**.

## Boundaries and future integration

Training and inference do not invoke LLMs, tools, policy, approvals, response,
adaptive planning, SecurityAI wrappers, or registry registration. They do not
mutate IncidentState or create Evidence, Observation, or AISignal.

```text
Offline auth dataset ──→ source adapter ──┐
                                       ├─→ finite window aggregation → FeatureSet → Auth AI
Authentication stream → source adapter ─┘

Network Telemetry ──→ Network AI ────────┐
                                       ├─→ Future AI Signals → SOC Investigation
Authentication Logs → Auth AI ──────────┘
```

Future stream ingestion joins at the source adapter; transport and watermarking
are outside this phase. Phase 3-5 evaluates real data, chronological splits,
thresholds and calibration. Phase 3-6 can wrap the validated detector using the
existing SecurityAI boundary, preserving feature/model provenance into results
and signals. Phase 3-7 may reason about independent network/auth signals; no fusion
or automated account locking/IP blocking exists here.
