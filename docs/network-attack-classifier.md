# Phase 3-2: Network attack classifier baseline

## Scope and data availability

This is a local, CPU XGBoost multiclass pipeline with a versioned feature contract,
not an Agent, streaming consumer, or SecurityAI production adapter. No actual
CIC-IDS2017 CSV was present during implementation. No dataset is downloaded.
**NO REAL CIC-IDS2017 METRICS AVAILABLE.** Synthetic fixture tests measure pipeline
behavior only, never operational IDS detection quality.

Local files belong in `data/raw/cicids2017/`. The adapter supports an explicit
CIC-like column dialect below. The actual release/columns must be inspected before
training; unsupported spellings fail rather than being silently mapped. Dataset
version `1` denotes the caller's local dataset snapshot contract, not a claim that
an official release carries that version. Exact CSV SHA-256 digests are retained.

## Feature contract and feasibility audit

`network_attack_features@1.0.0`, extractor `network_flow@1.0.0`:

| CSV field | Feature | Feasibility | Runtime requirement |
| --- | --- | --- | --- |
| Flow Duration | duration_us | DERIVABLE | Flow duration in microseconds, positive |
| Total Fwd Packets | fwd_packets | DERIVABLE | Count in initiating direction |
| Total Backward Packets | bwd_packets | DERIVABLE | Count in reverse direction |
| Total Length of Fwd Packets | fwd_bytes | DERIVABLE | Match CIC flow-meter packet-length semantics |
| Total Length of Bwd Packets | bwd_bytes | DERIVABLE | Same length accounting, reverse direction |

These five behavioral statistics are a conservative deployment-oriented baseline,
not a claim they are sufficient to distinguish all attacks. Byte accounting,
bidirectional flow keys, initiator direction, timeouts, truncation, offloading and
flow completion must agree offline/online. Kernel counters alone do not establish
that equivalence. No runtime parity with actual CICFlowMeter/eBPF was measured.
Other columns are UNKNOWN for this contract and excluded; none are retained merely
to improve fixture accuracy. Dataset-specific target fields are not features.

Column normalization only strips surrounding whitespace/BOM. Duplicate normalized
names, missing required columns, malformed widths and missing labels fail. CSV
numeric strings are explicitly parsed at the adapter boundary; non-duration counts
must be integral. SecurityRecord contains only normalized behavioral fields and a
separate declared Label. NetworkFeatureExtractor removes Label and validates the
same source schema used for STREAM records. FeatureSchema controls order everywhere.

Flow ID, IP addresses, ports, timestamp, Label and every non-allowlisted column are
excluded from model inputs. Inspection records the actual excluded column names:
Label/targets are excluded to prevent direct target leakage; identifiers/time avoid
memorizing collection conditions; all remaining fields lack an approved v1 contract.
This is an allowlist, not automatic correlation-based feature deletion.

## Inspection and invalid-data policy

Inspection reports files/digests, row counts, normalized columns, inferred
numeric/text types, labels/distributions, missing/NaN/Infinity counts, exact full-row
duplicates, and constant columns. Types are inferred from CSV strings, not an
assertion of original source dtypes. Duplicate counts are per file; split grouping
also detects identical selected feature inputs across files. Constant features are
reported but never silently dropped.

Default `invalid_policy=reject` stops on invalid selected values/labels. Explicit
`drop` discards bad rows and records their IDs and policy in dataset/training metadata.
Unselected invalid numeric columns remain visible in inspection but do not affect
input validity. Infinity is not silently passed to XGBoost. No median fitting,
zero-fill, implicit imputation, or native-missing behavior is used. Runtime rejects
missing/nonfinite/negative values and nonpositive duration under the same contract.
The final matrix projection is ordered float32, with explicit finite/range checks.
Float32 rounding is part of preprocessing, not a claim of exact integer precision
for arbitrarily large counters. The preprocessing identifier is artifact-bound.

An explicit timezone-aware `observed_at` reference is required for dataset ingestion.
This is a caller-supplied dataset observation reference, not a fabricated row-level
flow timestamp. A future real source adapter can parse actual timestamps separately.

## Leakage-safe split policy

The baseline uses five shuffled StratifiedGroupKFold folds with seed 42: fold 0 test,
fold 1 validation, folds 2–4 train (approximately 60/20/20). A group is formed from
bidirectional IP/port/protocol endpoints when available, otherwise Flow ID, otherwise
CSV filename. Time is never a model feature. Endpoint reuse deliberately groups
multiple sessions conservatively. Without flow identifiers, entire capture files
stay together, so random per-row splitting cannot masquerade as independent testing.

Groups connected by identical feature fingerprints are unioned before splitting.
Identical inputs with conflicting labels fail. Each class requires at least five
independent groups; every partition must contain every class. Insufficient rare
classes/groups fail with a specific error; there is no silent class removal, random
split fallback, retry search for a better seed, or automatic relaxation. CIC attack
classes concentrated in one capture day may therefore make this baseline split
impossible. Obtain independently captured groups or design/report a separate
held-out temporal evaluation before claiming real-dataset performance.

This is a grouped baseline, not proof against near-duplicates or shared collection
conditions. It does not substitute for cross-day/cross-network external validation.
Metadata retains partition indices, row IDs, group assignments, input fingerprints,
source file digests, grouping policy and seed. Labels are sorted deterministically;
their tuple order is the integer class encoding stored in the artifact contract.

## Model and evaluation

Native XGBoost `multi:softprob`, CPU hist trees, nthread=1, seed=42,
40 boosting rounds, depth=3, eta=0.1, subsample=1 and colsample_bytree=1.
Tests use five/two rounds. No tuning/search/early stopping or resampling is performed.
Training uses train only. Validation is reported during fitting and evaluated
separately; test is evaluated after fitting and does not select hyperparameters.

Metrics include accuracy, macro precision/recall/F1, weighted F1, per-class
precision/recall/F1/support, and a confusion matrix in artifact class order.
Zero-division metrics explicitly use zero. Macro F1 weights classes equally, helping
expose rare-attack failures hidden by benign-dominated accuracy. Stratification,
per-class support and macro metrics address visibility of imbalance; they do not
solve it. Calibration/weighting decisions belong to Phase 3-5.

**XGBoost softmax probability is treated as model confidence for the baseline, not
as a calibrated probability.** Confidence is the maximum class probability.
Prediction contains the selected class plus all class probabilities; their keys
match the contract classes and sum approximately to one. No SecurityAIRegistry
registration or AISignal conversion occurs in this phase.

## Native artifact and runtime validation

`save_artifact(result, output_dir)` creates:

```text
output_dir/network_attack_xgb/<version>/
    model.json
    metadata.json
    manifest.json
```

No existing version is overwritten. Manifest is written last; incomplete writes
cannot load. Metadata includes exact feature schema/order, extractor version,
preprocessing identifier, class mapping, dataset digests, split metadata,
hyperparameters, metrics and Python/numpy/sklearn/XGBoost versions. Native model
attributes bind the feature contract and a hash of training metadata. Manifest
contains SHA-256 hashes of native model bytes and metadata bytes. Loading verifies
hashes before parsing the model, then verifies metadata/contract/feature ordering.
A caller may pin the manifest digest from a trusted deployment source. This enables
future identity `(name, version, artifact digest)` without changing SecurityAI APIs.

Checksums detect corruption or replacement relative to a trusted manifest; they
are not signatures. An attacker replacing every file and all unpinned digests is
outside this integrity guarantee. Load only trusted artifacts, never arbitrary
user-selected model files. No pickle/joblib, dynamic import or fallback model exists.
Runtime FeatureSet schema, order and extractor must match exactly; no zero-fill,
column reordering guess, or silent schema upgrade is allowed.

## Offline → streaming bridge

Dataset and STREAM records with identical normalized values use the same extractor
and feature contract, giving identical input_fingerprint but different provenance.
The loaded classifier produces the same prediction for both. The fixture scenario
checks this complete train → evaluate → save → load → infer path.

```text
Kernel/eBPF → Security Telemetry → Data Bus → Network Source Adapter
    → Network Feature Extractor → FeatureSet → Network Attack Classifier
    → future SecurityAI Adapter → AISignal → SOC Agent
```

Source adapters own ingestion, units and flow aggregation; the model does not own
CSV reading or transport. Kernel collection/filtering/aggregation and userspace ML
runtime remain separate. Phase 3-6 can wrap this classifier in an async SecurityAI
handler, convert class probabilities to prediction/confidence/scores, and register
the wrapper through trusted setup. Resource limits, feature-set/result binding and
artifact digest enforcement need explicit integration there.

## Commands and limits

```bash
uv run python -m soc_agent.security_ai.network.train \
  --data-dir data/raw/cicids2017 --inspect-only
uv run python -m soc_agent.security_ai.network.train \
  --data-dir data/raw/cicids2017 --output-dir artifacts \
  --observed-at 2017-07-07T00:00:00+00:00 --model-version 1.0.0
```

The observation reference above is an example supplied by the operator, not an
automatic inference about the files. No real dataset is bundled or downloaded.
No work occurs on import. CSV uses the standard library; pandas is unnecessary.
ML modules require numpy, scikit-learn and xgboost. CPU execution does not require
GPU hardware even if an upstream wheel bundles GPU support libraries.

This first adapter/trainer holds rows and FeatureSets in memory. Full CIC corpus
throughput/memory is not benchmarked; production-scale batching/external memory is
future work. No claims of real IDS quality, sensor parity or calibrated confidence
are made from synthetic fixtures. SecurityAI production adapters, IsolationForest,
fusion, eBPF, data buses, model retraining and self-improvement remain deferred.

## Recorded synthetic pipeline check

The end-to-end fixture contains 120 generated rows, four artificial classes
(BENIGN, BruteForce, DoS, PortScan), and five features. With seed 42, depth 2 and
five rounds, the split is 72 train / 24 validation / 24 test rows. The observed
synthetic test metrics were:

| Metric | Synthetic pipeline test value |
| --- | --- |
| Accuracy | 0.875000 |
| Macro precision | 0.880952 |
| Macro recall | 0.875000 |
| Macro F1 | 0.874709 |
| Weighted F1 | 0.874709 |

Environment: numpy 2.5.3, scikit-learn 1.9.1, XGBoost 3.4.1, Python 3.12.14.
These measurements are not expected-score assertions in tests. Tests verify
metric structure and an independent small known confusion matrix instead.
**Fixture metrics are synthetic pipeline-test metrics and are not CIC-IDS2017
security performance. Actual CIC-IDS2017 metrics were not measured.**
