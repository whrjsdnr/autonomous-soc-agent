# Phase 3-6 — model packaging and explicit SecurityAI adapters

## Scope

Three fitted models can be exported, loaded, and used through the existing async
`SecurityAI[FeatureSet]` contract. This is offline packaging and inference, not
retraining, self-improvement or production deployment approval. Existing model,
training, artifact, SecurityAI and Registry APIs remain unchanged.

## Package format v1

Each package is a new directory containing exactly:

```text
manifest.json
metadata.json                 # complete immutable Phase 3-5 SelectionReport
model/model.json              # native XGBoost JSON or numerical forest JSON
preprocessing/profile.json    # full contract or frozen IF inference profile
```

The manifest contains package format version, model ID/version/kind, schema
name/version, extractor name/version, ordered feature names, canonical training
configuration, operating point, temperature, selection digest and three file
SHA-256 entries. Training configuration remains canonical JSON text, consistent
with the existing SelectionReport contract. Class mapping is in the classifier
contract and native model's embedded `feature_contract`; IF scaler, configuration,
normalization method/reference/offset and effective max_samples are in its profile.

`save_package(frozen_selection, new_path)` returns the SHA-256 of manifest bytes.
`load_package(path, expected_manifest_digest=trusted_digest)` requires this pin;
there is no unpinned load path. The manifest hash protects the inventory and all
metadata; its file hashes protect the other three files. Selection metadata is
rehash-checked against the manifest and validated against the profile's exact
`selected_binding`. Existing `final_test.selection_digest` identifies that same
selection, not a new evaluation after packaging.

Only the exact relative file names above are supported. Absolute paths, traversal,
duplicate inventory entries, duplicate JSON keys, unknown formats, missing/extra
files/directories, symlinks (including parent directories), FIFOs and nonregular
files are rejected. Reads use directory-relative file descriptors and `O_NOFOLLOW`.
Each file is limited to 16 MiB and the complete package to 32 MiB; bytes are read
once, hashed, then parsed from the verified bytes. No archives or decompression
are supported. These filesystem operations currently target Linux/POSIX.

Exports never overwrite an existing target and write the manifest last. The
output parent must be trusted, writable and free of concurrent writers; export
is not a transactional deployment mechanism. A failed export may leave a partial
directory; no registry is touched. Create a fresh output directory for a retry.

SHA-256 detects changes relative to a **trusted pin**, not publisher identity.
A hash delivered by the same untrusted party as the package supplies no
independent authenticity. Store/deploy pins through trusted configuration; signing,
key distribution, rollback policy and publisher authorization remain future work.
Native XGBoost parsing still trusts the native library and the approved publisher;
this format is not a sandbox for arbitrary hostile model programs. The in-memory
objects and direct constructors are trusted Python, not an anti-tampering boundary.

## Model formats and equivalence

XGBoost uses the same `save_raw(raw_format="json")` / `load_model(bytearray(...))`
mechanism as `network.artifacts`. The old TrainingResult artifact wrapper cannot
express Phase 3-5 selected/calibrated bundles, so it is retained intact while the
new envelope uses SelectionReport. Loading verifies native feature count, class
count, multiclass probability objective, boosting rounds, feature order and the
embedded class/feature contract before exposing the model. Probabilities remain
in contract class order; positive-temperature scaling uses the existing evaluator.
T=1 returns the original probabilities unchanged.

IsolationForest uses **no pickle/joblib deserialization and no sklearn Tree object
reconstruction**. Export supports the inspected fitted sklearn **1.9.1** structure,
full feature participation, no bootstrap, no warm start, and fixed n_jobs=1.
Other export versions/configurations fail explicitly. Numerical format v1 stores
only children, feature indices, float64 thresholds and node sample counts, plus
feature count and effective max_samples. No `__dict__`, callable or import path is
serialized. At most 1,000 trees, 65,536 samples/tree, 64 features and 200,000 total
nodes are allowed, in addition to file limits. Integer indices are strict;
nonfinite thresholds, wrong lengths, cycles, shared/unreachable children, invalid
sentinels, invalid sample counts, inconsistent parent/child populations and excess
depth are rejected before scoring.

The numerical scorer reproduces installed sklearn's `_compute_score_samples` and
`_average_path_length`: convert scaled inputs to float32, traverse with `<=` against
float64 thresholds, accumulate root-inclusive depth plus leaf path correction
minus one in tree order, then return `-2 ** (-depth / (trees * c(max_samples)))`.
For leaf populations 1 and 2, c(n) is 0 and 1; otherwise it uses sklearn's log/Euler
constant approximation. Explicit conversion of the float32 value to Python float
before comparison prevents NumPy scalar promotion from rounding a split threshold.

Scalers and empirical-midrank normal references are loaded verbatim, never fitted.
Raw anomaly measure is `-score_samples`; normalized score uses the existing frozen
reference. Neither score is an attack probability. `ModelPackage.predict` preserves
the existing normalized decision semantics. `operating_decision` applies the
separately selected operating point. Exact equality, rather than widened tolerance,
is asserted for both scores on development rows and tree split boundaries. Different
future numeric/native library versions need fresh equivalence tests before support.

## Adapter contract and explicit registration

`NetworkClassifierAdapter`, `NetworkAnomalyAdapter` and
`AuthenticationAnomalyAdapter` expose `as_security_ai()`. They receive already
extracted FeatureSets through the existing request envelope. Use the existing
NetworkFeatureExtractor or AuthenticationWindowExtractor first:

```text
SecurityRecord(s) -> existing extractor -> validated FeatureSet
-> SecurityAIRequest[FeatureSet] -> packaged handler -> SecurityAIResult
```

There is no raw-record inference overload and no new extractor. Authentication
uses account-based, nonempty 300-second windows. Inputs are revalidated for full
schema, feature order, extractor identity/version, numeric ranges and provenance
shape, source record contract and request incident consistency. Authentication and
network schemas cannot be interchanged. Provenance is structural lineage, not proof
that caller-created measurements are true; trusted extractors validate original
records and referenced evidence upstream. Adapters do not inspect or change state.

Example after a trusted setup has obtained `trusted_digest` and extracted `features`:

```python
from pathlib import Path
from soc_agent.security_ai import SecurityAIRegistry
from soc_agent.security_ai.models import SecurityAIRequest
from soc_agent.security_ai.packaging import load_package, NetworkAnomalyAdapter

package = load_package(Path("network-package"), expected_manifest_digest=trusted_digest)
model = NetworkAnomalyAdapter(package).as_security_ai()
registry = SecurityAIRegistry()
registry.register(model)  # explicit; load/import never register
result = await registry.get(model.metadata.name).predict(
    SecurityAIRequest(incident_id=incident_id, input=features)
)
```

Classifier results contain class probabilities and classifier confidence. Anomaly
results have `confidence=None`, label normal/anomaly from the **selected raw**
threshold, raw/normalized scores, and both selected and legacy normalized decisions.
Explanations retain feature fingerprint, feature provenance, manifest/selection
digests, operating point and its identity digest. Equal offline/stream measurements
produce equal predictions and fingerprints, while provenance remains distinct.
Inference creates only SecurityAIResult; no Evidence, Observation, Hypothesis,
AISignal, IncidentState change, policy/approval/tool/response action or auto-blocking
occurs. Registry accepts only explicit wrappers; duplicate registration and failed
loads leave previous entries untouched. There is no batch registration API or
implicit partial batch installation.

## Phase 3-5 handoff

All selected models use version 1.1.0 and seed 42. Exact selections are reconstructed
from fixed development generators, and their report digests must match the checked
Phase 3-5 JSON before packaging. No holdout-based reselection occurs.

| Model | Selected settings | Adapter operating point | Legacy threshold |
|---|---|---|---|
| Network XGBoost | 60 trees, depth 2, learning rate .1 | Argmax, T=1; no calibration | N/A |
| Network IF | 128 trees, max_samples 256/effective 60, contamination auto | raw >= .4508608194824563 | normalized .95 |
| Authentication IF | 64 trees, max_samples 256/effective 30, contamination auto | raw >= .5604416052073505 | normalized .95 |

Network binds `network_attack_features@1.0.0`, `network_flow@1.0.0` and ordered
`duration_us, fwd_packets, bwd_packets, fwd_bytes, bwd_bytes`. Authentication binds
`authentication_behavior_features@1.0.0` and `authentication_window@1.0.0`;
its complete ordered schema is stored in the profile, checked against the existing
extractor definition, and duplicated as ordered names in the manifest.

| Model | Selection SHA-256 |
|---|---|
| Network XGBoost | `ac86f539b17875d1c70f38e949ddcaa46bda3d772aabe349dc5ab074a8e0586b` |
| Network IF | `82f64afe31da65eb04bb84af6061cb734640c0381091ba46034f26a856feadba` |
| Authentication IF | `587ebdb1287593b090b7b16284f567ef78e059d631586c259ddc83439ec2b393` |

These are synthetic experimental settings, **not operationally approved values**.
Network IF holdout F1 rose .809756 -> .944000, but FPR rose .05 -> .30 (2 -> 12 false
alerts among 40 normal samples). Auth FPR rose 0 -> .10. Packaging does not improve
these trade-offs or establish real-world generalization. See
[the evaluation report](security-ai-evaluation.md) for shared generator assumptions.

## Reproduction and remaining deployment work

```bash
UV_CACHE_DIR=/tmp/soc-network-ai-uv-cache uv run --offline \
  python -m tests.run_security_ai_packaging --output /tmp/soc-phase3-6-packages
```

The output must not already exist. The runner writes three packages and an external
`package-pins.json`, actually loads all three and checks predictions on 400 network
rows per model and 100 authentication windows. The pins file is a local handoff
record, not a signature or a source of trust for arbitrary downloaded packages.
Generated models stay out of Git. Tests cover artifact corruption, semantic
mismatch even after rehashing an inventory, path/resource controls, exact inference,
invalid adapter input, explicit registry behavior and a three-model end-to-end
record/extractor scenario.

Phase 3-7 can consume these explicit wrappers and trusted pins. Real security data,
site/time holdouts, probability reliability, operational FPR budgets, publisher
verification, deployment approval, atomic deployment/rollback and safe model update
procedures remain unimplemented. Do not infer automatic action authority from a
loaded or registered model.

## Verified result (2026-09-21)

- New unit tests: 77 passed; new three-model end-to-end scenario: 1 passed.
- Full regression: **1,217 passed in 247.27 seconds**, exit code 0; existing 1,139
  tests retained without weakened assertions.
- Ruff check and format check passed (237 Python files); five packaging module
  imports and `git diff --check` passed.
- Reproduction runner completed actual save/load/inference on 400 classifier rows,
  400 network anomaly rows and 100 authentication windows. Predictions and anomaly
  scores/decisions matched exactly. All three selection digests matched Phase 3-5.
- Generated packages and manifest pins are in `/tmp/soc-phase3-6-packages` for this
  workspace run; these temporary files are not committed deployment assets.
- Package sizes: classifier 248,968 bytes; network IF 232,531 bytes; authentication
  IF 81,586 bytes. The runner's `package-pins.json` records exact manifest hashes.
- No commit or push was performed. Existing public APIs and agent/governance code
  were not modified.
