# Phase 3-5 — offline evaluation and bounded improvement

## Scope and reproduction

This is an offline experiment system, not automatic production self-improvement.
There is **no real CIC-IDS2017 or enterprise authentication dataset** in the repository.
All results below are synthetic pipeline-test results. External security
generalization is **not measured**.

Reproduce the fixed experiment (temporary CSVs are deleted automatically):

```bash
UV_CACHE_DIR=/tmp/soc-network-ai-uv-cache uv run --offline \
  python -m tests.run_security_ai_evaluation --output /tmp/security-ai-evaluation.json
```

The measured, structured report is [synthetic-phase3-5.json](evaluation/synthetic-phase3-5.json).
It records every candidate, every threshold trial, calibration trials, per-class
metrics, confusion matrices, probability reliability bins, train metrics, source
file digests, partition audits, configuration bindings and library versions.
The report is metadata, not a serialized model or raw dataset.
The detailed JSON is approximately 580 KiB; this Markdown is its human-readable
summary. Keep the full candidate/threshold/audit records in JSON rather than
discarding unsuccessful trials to shrink it.

## Data quality and split audit

FeatureSchema, extractor identity and feature order are unchanged. Network uses
`network_attack_features@1.0.0`; authentication uses
`authentication_behavior_features@1.0.0` with five-minute windows.

The new development generator is version 1, seeds 3501 (network) and 3502 (auth).
Network generates overlapping lognormal behavioral statistics, passes actual CSVs
through the existing CIC adapter, and uses distinct flow groups. Authentication
generates finite events through the existing adapter/window extractor, with both
normal and anomalous windows per account. Labels stay outside model inputs.

| Population | Train | Selection | Calibration | Reserved outer test | Independent test |
|---|---:|---:|---:|---:|---:|
| Network IF (400 development rows) | 240 | 80 | — | 80 unused | 160 |
| XGBoost (same development rows) | 240 | 40 | 40 | 80 unused | same 160 |
| Auth IF (100 development windows / 50 accounts) | 60 | 20 | — | 20 unused | 40 / 20 accounts |

Network IF fits 60 BENIGN train rows; auth IF fits 30 normal train windows.
Scaler fitting and score reference fitting use only these rows. No label is
passed as IsolationForest's `y`. XGBoost fits all 240 train rows.

The shared StratifiedGroupKFold-5 split (seed 42) groups related flows/accounts and
identical feature fingerprints together. Authentication source event IDs are
carried into evaluation rows. Cross-partition group, fingerprint, event and logical
source overlap fails before fitting or final evaluation. Each class needs five
independent groups. No random fallback, seed search, or silent class deletion.
XGBoost validation is split once using GroupShuffleSplit (seed 42); every class
must remain in both halves. If it cannot, calibration splitting fails explicitly.

Accepted inputs have zero missing/nonfinite values. FeatureSet validation rejects
invalid values before fitting; the existing CSV inspection records raw invalid
numeric counts, constant columns, duplicates and file SHA-256. The new audit
records class/group populations, normal availability, duplicate input rows and
cross-group duplicates. Duplicate inputs within a partition are reportable, not
inherently errors; leakage across partitions is rejected. This experiment has
zero duplicate input leakage. Audits record each partition's class counts and
group/class counts to expose distribution differences. XGBoost selection contains
9/11/9/11 rows in BENIGN/BruteForce/DoS/PortScan order; calibration has 11/9/11/9.
Train and independent network test are balanced. Auth partitions are balanced.

Reports hash group identities rather than printing raw accounts or IPs. These
hashes are pseudonyms, not a claim of cryptographic anonymization. Content digests
include label, input fingerprint and source provenance, excluding newly allocated
FeatureSet IDs/timestamps; split strategy and seed are recorded separately.

## Previously exposed fixture: diagnosis only

The original fixtures were already observed before Phase 3-5. They are **not blind
tests**, are remeasured only for regression/diagnosis, and do not select candidates.
Their small-model configurations differ from the new default baseline experiment.

| Previously observed model | Remeasured result |
|---|---|
| XGBoost, 5 trees / depth 2 | Accuracy .875; Macro F1 .874709 |
| Network IF, 16 trees / normalized .95 | Precision/Recall/F1 0; ROC-AUC .75; AP .90 |
| Auth IF, 16 trees / normalized .95 | Precision .75; Recall 1; F1 .857143; ROC-AUC .666667; AP .75 |

### Why the old network IF missed all 18 attacks

Direct score measurements on its already observed test show:

- All 18 attacks have identical raw anomaly measure **0.5790185999** and normalized
  score **0.9166666667**, strictly below the fixed 0.95 threshold.
- BENIGN raw measures range **0.4838651434–0.6277933145**, with normalized scores
  **0.2777777778–0.9722222222**. One benign sample exceeds 0.95.
- Thus confusion is `[[5,1],[18,0]]`: a cutoff/ranking distinction, not an AUC bug.
- The 18-row reference yields coarse half-ranks (1/36). Attack raw scores are
  already tied; this is not just percentile clipping at 1. The tree model gives
  those distant measurements the same score. Some benign observations rank above
  attacks, so a threshold cannot create perfect separation from those scores.
- Validation independently shows attack score .916667, above benign validation's
  .5–.777778 yet below .95. This supports examining thresholds without consulting
  final holdout labels.

These measurements explain this fixture, not a universal IsolationForest failure
or proof that different real-world features would improve detection.

## Predeclared candidates and selection

The candidate/generator code was fixed before independent holdout results were
observed. No candidate, feature, threshold grid or seed was retuned after test.

- IF: 64 and 128 trees; effective max_samples=min(256, normal train count), seed 42,
  contamination auto, n_jobs=1. Duplicate effective configurations are rejected.
- Thresholds: normalized .95 (baseline), .5, .75, .9; up to 64 ordered validation
  raw-score cutpoints and one just above the maximum (all-negative).
- Objective: maximize **validation F1**. Baseline wins objective ties; subsequent
  threshold ties prefer lower FPR then fixed order. Model ties retain the earlier
  predefined candidate. A separate helper supports recall under an explicit FPR
  limit, tested but not the objective of this experiment.
- XGBoost: (trees, depth, learning_rate) = **(40,3,.1)** baseline,
  **(60,2,.1)**, **(40,3,.05)**. Select by validation Macro F1; baseline wins ties.
- No feature changes, window changes, Optuna, automatic retraining, or deployment.

| Model / candidate | Validation primary metric | FPR | Selection |
|---|---:|---:|---|
| Network IF 64 / normalized .95 | F1 .784314 | .10 | baseline |
| Network IF 64 / raw .4586762936 | F1 .936508 | .35 | rejected for lower F1 |
| Network IF 128 / raw **.4508608195** | **F1 .937500** | .40 | selected |
| Auth IF 64 / normalized .95 | F1 .181818 | .00 | baseline |
| Auth IF 64 / raw **.5604416052** | **F1 .947368** | .00 | selected |
| Auth IF 128 / raw .5506902372 | F1 .947368 | .00 | rejected: tie |
| XGBoost (40,3,.1) | Macro F1 .974937 | — | baseline |
| XGBoost (60,2,.1) | **Macro F1 1.000000** | — | selected |
| XGBoost (40,3,.05) | Macro F1 .924580 | — | rejected |

Most network IF validation improvement came from threshold selection. Doubling
trees adds only .000992 F1 beyond threshold-only tuning while increasing validation
FPR .35→.40. It is weak evidence for a model-capacity benefit. Auth's extra trees
provide no further validation improvement. XGBoost train Macro F1 is 1.0 for the
baseline and selected candidate, and .995833 for the lower-learning-rate candidate;
small validation samples cannot rule out overfitting.

Validation operating-point changes (baseline → selected) are:

| Model | Precision | Recall | FPR |
|---|---:|---:|---:|
| Network IF | .952381 → .882353 | .666667 → 1.000000 | .10 → .40 |
| Auth IF | 1.000000 → 1.000000 | .100000 → .900000 | .00 → .00 |

## Probability calibration versus anomaly operating point

IF raw/percentile scores remain ranking measures, **not attack probabilities**.
Raw thresholds are stored as explicit `OperatingPoint(space="raw", threshold=...)`
sidecars. Existing detector prediction APIs retain their original normalized
threshold semantics; the evaluation bundle applies the selected sidecar. Never
silently reinterpret the existing prediction's `threshold` as a raw threshold.

For XGBoost, temperature scaling uses stable log probabilities, maximum subtraction,
softmax and unchanged class order. T candidates: 1, .5, .75, 1.5, 2, 3. Fit by
calibration-half log loss; accept only if separate selection-half log loss strictly
improves and Brier does not worsen. Class accuracy/Macro F1 are reported separately
and positive temperature scaling preserves the argmax.

Calibration fitting chose **T=1 (no change)**. NLL at T=1 was .321747; at T=1.5 it
was .352538, even though Brier decreased .195717→.191934. The NLL objective did not
justify applying it. Selection before/after NLL remains **.102535**, Brier
**.038538**. No calibration improvement is claimed. Tiny synthetic calibration data
cannot establish operational probability reliability.

Multiclass Brier is mean sum of squared class errors (not divided by class count).
Reliability summaries use ten fixed top-confidence bins. Probability column/class
order mismatch is rejected. Average Precision is sklearn's step-integral summary,
**not trapezoidal PR-AUC**. Binary AUC/AP are None for single-class populations;
FPR is None without negatives. Zero-division precision/recall/F1 is zero.

## Frozen configurations and independent synthetic test

`select_classifier` and `select_anomaly` accept train/selection roles; test roles
are rejected. Calibration has a separate role. The immutable selection report and
in-memory bundle are created before `evaluate_test`, which only predicts and
reports. Configuration substitution is rejected. Low-level metric functions take
arrays and cannot infer their origin; honest partition labeling remains an
application responsibility, not protection from malicious Python code.

Only after **all three** selections were frozen were holdout seeds 3591 (network)
and 3592 (auth) used. Groups/source/event identities are distinct. Auth uses even
successful-login counts in development and odd counts in holdout to preclude exact
feature-vector duplication by construction; this is an artificial fixture design,
not an independent real-world population. Existing outer test folds remain unused.
The new holdout was unused for initial selection, but is now a reproducible,
observed regression fixture—not a permanently blind benchmark.

Different random seeds establish separate generated samples, not real-data
generalization. Development and holdout share the same class-dependent network
means, lognormal noise recipe, feature definitions and balanced class counts.
Authentication shares the same label-dependent failure/success ranges and two
nonempty windows per account, with an artificial parity difference. Neither
generator models real attack prevalence, unseen attack families, site differences,
temporal drift, missing telemetry or adversarial adaptation. In particular, the
network population is 75% attacks and authentication is 50% anomalous; measured
precision must not be projected onto a low-prevalence SOC workload.

| Model | Test metric | Baseline | Selected |
|---|---|---:|---:|
| XGBoost | Accuracy | .937500 | **.962500** |
| XGBoost | Macro F1 | .937642 | **.962494** |
| XGBoost | Log loss | .208471 | .159840 |
| XGBoost | Brier | .097090 | .076847 |
| Network IF | Precision | .976471 | .907692 |
| Network IF | Recall | .691667 | **.983333** |
| Network IF | F1 | .809756 | **.944000** |
| Network IF | FPR | .050000 | **.300000 (worse)** |
| Network IF | ROC-AUC / AP | .952917 / .983018 | .959375 / .985107 |
| Auth IF | Precision | 1.000000 | .900000 |
| Auth IF | Recall | .400000 | **.900000** |
| Auth IF | F1 | .571429 | **.900000** |
| Auth IF | FPR | .000000 | **.100000 (worse)** |
| Auth IF | ROC-AUC / AP | .980000 / .980939 | unchanged |

Selected IF confusion: network `[[28,12],[2,118]]`; auth `[[18,2],[2,18]]`.
Improved F1 does not imply an acceptable operational false-positive budget. No
production threshold is recommended from these results. No test-based reselection
was performed, including in response to worse FPR/precision.
Network false alerts increased from 2 to 12 among 40 benign holdout rows (sixfold),
while missed attacks fell from 37 to 2. Authentication false alerts increased from
0 to 2 among 20 normal windows, while misses fell from 12 to 2. No analyst-time or
monetary cost was measured; the F1 objective imposes no operational FPR budget.

XGBoost baseline's weakest class is BruteForce (recall .90, F1 .888889), confused
with BENIGN/DoS/PortScan; selected recall is .95 and F1 .938272. Selected recalls are
BENIGN .95, BruteForce .95, DoS .95, PortScan 1.0. Full per-class precision, recall,
F1, support and confusion matrices are preserved, not hidden by Macro F1.

Auth false positives cover two distinct held-out accounts, not repeated windows of
one account. Their mean failure rate is .08446 and attempts/second .36167, versus
true negatives .04389/.31259. False negatives average failure rate .30262; true
positives .54154. These are descriptive error slices, **not causal feature
importance**. Even normal five-minute bursts can be flagged. Account-disjoint
splits reduce memorization but do not demonstrate temporal robustness or tenant
transfer; all windows here are nonempty and generated from a narrow recipe.

## Engineering boundaries and Phase 3-6

Existing training/evaluation APIs and artifact formats remain supported. New
fit-only helpers prevent candidate search from accidentally invoking old combined
train/validation/test routines. Network/auth scaler, normalization and model code
retain their behavior. Existing native XGBoost artifact integrity checks are
unchanged. New selected bundles are **in-memory only** and are not passed to the
old artifact saver; no calibrated wrapper is silently serialized without metadata.

Phase 3-6 must bind model bytes/digest, feature/extractor/class mapping, selected
configuration, temperature or raw/normalized operating point, IF scaler/reference,
and the selection report digest into an explicit package. No pickle/joblib loading
is added here. Model private internals remain trusted Python objects.

The concrete experimental handoff is below; these are packaging inputs, not
approved production operating points. All use seed 42 and model version 1.1.0.

| Model | Selected configuration | Operating point / calibration | Schema and extractor |
|---|---|---|---|
| Network XGBoost | 60 trees, depth 2, learning rate .1 | Argmax in BENIGN/BruteForce/DoS/PortScan order; T=1, calibration method none | network_attack_features@1.0.0; network_flow@1.0.0 |
| Network IF | 128 trees, max_samples 256 (effective 60), contamination auto, n_jobs 1 | raw >= .4508608194824563 | network_attack_features@1.0.0; network_flow@1.0.0 |
| Auth IF | 64 trees, max_samples 256 (effective 30), contamination auto, n_jobs 1 | raw >= .5604416052073505 | authentication_behavior_features@1.0.0; authentication_window@1.0.0; 300-second windows |

Both IF profiles retain normalized threshold .95 for their existing public APIs;
the raw operating points must be packaged separately and explicitly applied.
Persist the exact ordered feature definitions from `selected_binding`, not just
the schema name. Bind IF scaler and normal-reference scores to the model bytes.
The selection-report SHA-256 values below match `final_test.selection_digest`:

| Model | Selection digest |
|---|---|
| Network XGBoost | `ac86f539b17875d1c70f38e949ddcaa46bda3d772aabe349dc5ab074a8e0586b` |
| Network IF | `82f64afe31da65eb04bb84af6061cb734640c0381091ba46034f26a856feadba` |
| Auth IF | `587ebdb1287593b090b7b16284f567ef78e059d631586c259ddc83439ec2b393` |

This digest binds the selection report and its configuration/provenance metadata;
it is not a digest of fitted model bytes or proof against mutation of trusted
Python model internals. Phase 3-6 must add that artifact binding and validate
round-trip predictions and rejection of mismatched metadata using a safe format.

No LLM/tool/policy/approval/response/Agent execution, IncidentState mutation,
SecurityAIRegistry registration, AISignal creation, model fusion or self-modifying
production behavior occurs. No new dependency is added. Future work includes
real versioned data, temporal/site holdouts, confidence intervals, meaningful FPR
constraints, larger independent calibration cohorts and packaging.

## Final verification (2026-09-21)

The resumed session preserved the existing implementation and candidate settings.
It strengthened the scenario assertion to recompute the selection-report digest
and expanded the limitations, operating costs and packaging handoff above.

- Evaluation tests: 24 unit tests and 1 scenario passed (25 total).
- Full regression: `uv run --offline pytest -v` — 1139 passed in 128.37 seconds,
  including the strengthened scenario assertion; exit code 0.
- Ruff check passed; Ruff format check passed for all 225 Python files.
- Import smoke passed for eight evaluation/training/runner modules.
- `git diff --check` passed. No commit or push was performed.

All uv commands used `UV_CACHE_DIR=/tmp/soc-network-ai-uv-cache`. A fresh runner
output at `/tmp/security-ai-evaluation-verified.json` matched the checked report
byte for byte, including every candidate, metric, audit and freeze digest:
SHA-256 `f9525ade3ef733eab87e3d95ac6fd40a0da72a7c02b12e51d665c85551df8ca7`.
Reproduction of this now-observed fixture is an engineering consistency check,
not another independent estimate of generalization.
