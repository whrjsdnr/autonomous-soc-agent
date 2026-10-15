# Verified Network/DNS producer and retraining readiness

Date: 2026-10-15, WSL2 Ubuntu. SOC baseline
`4a86db4c0beeef7d6d7d81c1a0f7d543b27183b4`; ML baseline
`1800bd013edefd448671c97a8b7114409f639481`.

**Final scope verdict: BLOCKED for model retraining, independent evaluation and
operational model readiness.** Offline producer preparation is PARTIAL.
No retraining or native AI inference occurred. Operational gates remain closed.

| Model | New producer arithmetic | Raw labeled corpus | New training / holdout | Operational input |
|---|---|---|---|---|
| Network Quality | PARTIAL, 14 features | MISSING | BLOCKED | NOT_INFERABLE |
| Network Edge | PARTIAL, same new contract | MISSING | BLOCKED | NOT_INFERABLE |
| DNS Security | PARTIAL, 7 FQDN features | MISSING | BLOCKED | NOT_INFERABLE |

## 1. Ownership and inventory

Existing SOC modifications in README, Command Center docs, pyproject, Scenario
analysis, runtime CLI/feedback/service and tool errors are preserved. Untracked
Reliability Replay and unrelated outputs are excluded. ML's untracked
`packages/dns_security_package/` is preserved and excluded. No models/scalers,
existing package source, runtime, GUI, policy or provenance contracts were changed.
The index was empty in both repositories at the start.

[Portable contract snapshot](verified-producer-contracts.json) and
[sanitized evidence](verified-producer-evidence.json) are byte-identical to their
ML documentation counterparts. They do not import ML or change runtime behavior.
Detailed implementation/report lives in ML at `docs/verified-producer-retraining.md`.
SOC can test/ship its own documentation and boundary tests independently of ML.

## 2. Raw dataset feasibility

A fresh ML inventory found no PCAP/PCAPNG/CAP files in the inspected data/code/
package directories. Ten CSE-CIC-IDS2018 CSV headers under `data/raw` were checked:
nine have 80 columns, one has 84; total file size 6,886,649,507 bytes. They contain
precomputed flow features, not raw packet sequences for the new producer.
Source/Flow IDs in the larger schema cannot reconstruct raw per-packet timing.
Existing processed Parquet files are excluded from new-producer training.
This was filename/header inspection, not a full scan of all row contents.

DNS EDA/ML notebooks under ML `reports` read stateless-feature CSVs. Referenced
Benign and Attack CSV files are absent, and no raw FQDN corpus linked to independent
labels was found. Reading a feature CSV is not original feature production.
No new real training dataset or holdout exists; admitted samples are zero.
No classifier labels were derived from findings, model outputs or human approval.

Acquisition references checked on this run:
[UNB CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) distinguishes raw
PCAP/logs from its computed CSVs;
[UNB CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html) describes
the DNS dataset and labeling context. Need actual checksummed raw files plus
reviewed source/time/endpoint label mappings and domain/capture grouping.
No download was performed. Availability of a website does not verify local data.

## 3. New Network producer

ML `src/ml/verified_producers/network.py:Packet,network_features` implements
`linux-observable-network` version `1.0.0`, independently of Top40.

Features: duration; forward/backward observation counts and IP bytes; IP length
min/max/mean/population standard deviation; SYN/FIN/RST observation counts; mean
and max consecutive IAT. There are **14**, without padding to 40. Forward is the
first observed endpoint direction. IP bytes are not frame/payload bytes. No rates
or Active/Idle statistics are guessed. Singleton IAT is zero by explicit definition.

Input validation rejects missing/nonfinite/invalid fields, mixed interface/session/
flow, duplicate Event IDs, reverse time order and timeout-crossing segments.
Caller must segment first: interval >=30s or total span >=120s is rejected.
At most 4096 observations are accepted. GAPPED/DROPPED inputs are rejected;
UNKNOWN quality permits offline diagnostic arithmetic only. Metadata IDs and
source-origin strings are declarations, not proof of authenticity or completeness.
Loopback inbound/outbound copies remain observations, not deduplicated wire packets.

## 4. New DNS producer

ML `src/ml/verified_producers/dns.py:dns_features` implements
`linux-observable-dns` version `1.0.0`, independently of DNS9.

Its **7** features are name length without terminal root, label count, max/mean
label length, digit ratio, special ratio and character Shannon log2 entropy.
ASCII lowercase and exactly one terminal-dot removal are explicit. Labels are
1..63 ASCII alphanumeric/hyphen/underscore characters; total normalized length
<=253. Empty/root-only/Unicode/invalid names are rejected. ASCII Punycode is literal;
no implicit IDNA or public-suffix/subdomain inference occurs. Character statistics
exclude dots. Query type/TTL are omitted. A hashed name, DoH or DoT provides no
usable lexical population. This intentionally does not support all DNS wire labels.

## 5. Producer contract and Golden pairs

[Contract JSON](verified-producer-contracts.json) binds names/order, input schema,
version, direction/timeout/normalization/missing policy, precision and scaling.
Arithmetic is binary64 followed by one float32 conversion. No scaling is fitted.
Source and feature digests bind exact declared inputs/configuration/order/values;
SHA integrity is not authenticated provenance. Implementation source SHA256s are
recorded in [evidence](verified-producer-evidence.json).

ML's Golden fixture has **1 Network + 2 DNS hand-checked synthetic cases**.
Network uses times 0,1,3; lengths 40,80,40; F/B/F, with population variance 3200/9.
DNS samples have independently countable entropy 1 and 2 bits. Expected values
were not produced by the function under test; Network has a separate sum-of-squares
reference calculation. Pinned fixture SHA, order/config digest checks and 1e-6
absolute/relative comparison detect arithmetic/identity changes. These are small
reference samples, not original-training Golden Pairs or operational accuracy data.
Training and live use of the same function alone is not claimed as independent
parity evidence. New producers do not make existing models compatible.

## 6. Dataset and retraining status

ML `dataset.py:dataset_manifest` is a fail-closed **declaration validator**, not a
trainer. It rejects feature-only or synthetic inputs as training declarations,
derived/missing labels, duplicate source/sample IDs, group leakage and missing
splits/classes. Its output explicitly leaves raw-byte/label-authority/temporal
verification false and promotion blocked. It does not verify raw content or
independent group assignment. Test declaration counts are not training data.

Dataset generation, full raw/label join and split builder, retraining, learned
preprocessing, independent holdout evaluation and new artifact packaging are all
**BLOCKED / not implemented in this run**. There is no new model to load or test
for timeout. Precision/recall/F1/PR-AUC/confusion matrix/FPR/FNR/latency/RSS are N/A,
not fabricated zeros. Old package tests are not new-model validation.

Quality and Edge can later share a new producer but need separate artifact and
runtime validation. Fit transforms only on training; isolate source/session and
overlapping windows, and independent domain/source-family groups for DNS. A frozen
holdout cannot become repeated candidate-selection data. Exclude and count
ambiguous label joins. Report class imbalance and base-rate limits. Old models
with different inputs cannot be ranked without a comparable raw holdout.

## 7. Real WSL saved-source diagnostic

No new capture or privileged command was executed. Existing user-executed session
was read with SQLite `mode=ro`; all original files had identical SHA before/after.
Stored Queue digests and PacketObservation kernel timestamp/shape bindings passed.
**32 packet observations -> four diagnostic endpoint groups -> four new Network
feature vectors**. DNS events: **0**; independent training labels: **0**.

This is arithmetic over previously captured metadata, not live inference, not
new packet capture, and not a fresh Source Store/recovery certification. Existing
Capture Gap remains 1; quality is UNKNOWN, not complete. No new model, finding,
LLM investigation or operational action was generated. Sanitized vector digests
and values are in evidence JSON; raw addresses/payloads were not copied to reports.

## 8. SOC integration readiness and security

Current `NetworkPipeline` persists original packet metadata and diagnostic flows;
`FlowSummary` is incomplete/DIAGNOSTIC_ONLY. Producer input needs packet records,
not just that summary. Kernel ns timestamps and event/session/interface references
must be supplied after existing source/digest/provenance verification. DNS retention
is off by default; no raw-name feature can be reconstructed from the stored digest.
Privacy-approved explicit raw-name availability would be required in a later stage.

`ExternalSecurityAIService` v2 is synthetic-only; real records must not be relabeled
synthetic to fit it. OperationalProvenanceReceipt v3 still permits no live Network/
DNS model output. A reviewed future model binding/adapter/provenance change would
be necessary, followed by advisory-context/finding/investigation validation.
This run changes none of those contracts or the Runtime/GUI. No operational
promotion follows from importing the offline producer or loading its JSON spec.
Existing `model_gates()` keeps Quality, Edge and DNS independently NOT_INFERABLE;
inference/finding promotion BLOCKED; WRITE_DENIED remains enforced.

## 9. Tests and independent export

New SOC tests: `tests/unit/operational_features/test_retraining_readiness.py` checks
pinned spec identity, non-legacy dimensions, absent artifact, closed per-model
gates, raw-name privacy, fixture timestamps and v3 rejection of an offline spec.
Existing capture/source/provenance/native-adapter/runtime/GUI/approval/execution/
recovery tests are reused. AF_PACKET/INET test sockets are denied by the existing
audit-hook guard; no real LLM or capture is required. The unrelated untracked
`test_producer_parity_boundary.py` is excluded in both working and export runs.

ML new tests cover hand Golden values/digests, float32 determinism, missing/NaN/Inf,
normalization, IPv4/IPv6, malformed lengths, order/timeout, mixed sources, duplicate
observations, declaration trust and split leakage. Legacy tests run separately
from actual new-model training, which remains blocked. Exact executed totals and
export results are appended below. Repeated runs are not combined into one count.

## 10. Remaining blockers and next work

1. Obtain raw PCAP/FQDN and authoritative linked labels; review dataset/privacy/license.
2. Implement bounded raw-to-existing-parser import and label joins; freeze grouped,
   time-separated holdout with independently verified provenance and exclusions.
3. Expand independent Golden/reference coverage beyond the three hand fixtures,
   including real labeled captures, source gaps and DNS normalization boundaries.
4. Train/version Quality, Edge and DNS separately. Record seed, versions, configs,
   timings, dataset/split digests, holdout metrics, latency/RSS and SHA bundle.
5. Review compatibility and a separate operational adapter/gate decision; retain
   advisory/fact separation and authenticated approval for any response.
6. Physical Linux NIC/long-duration/capture-loss/base-rate validation is future work.

No model, code, policy, approval, OS security setting or runtime configuration was
automatically promoted or modified by the offline producer.

## 11. Executed validation ledger and change scope

| Execution | Result |
|---|---|
| New SOC readiness tests | 6 passed, 0 failed (0.31s); included in broad runs below |
| SOC working-tree related regression | 762 passed, 0 failed (240.97s) |
| ML final working-tree new + legacy package regression | 262 passed, 0 failed (4.05s) |
| ML independent export, new producer/admission tests | 66 passed, 0 failed (0.07s) |
| ML independent export, isolated standard-library smoke | 3 hand reference cases passed; no SOC imports/path |

Counts are per execution, not additive. Export SOC results are recorded in the
final row below after completion. LLM calls are disabled. The SOC audit-hook guard
blocked one socket-creation attempt during the working regression; it performed
no capture or generated traffic. Fixture/recovery checks are not live collection.

SOC full `ruff check src tests`, `ruff format --check .` and Git whitespace check
passed. The export also passes Ruff/Format. ML `ruff check src tests` and all seven
new Python files' format checks passed, including export. **ML repository-wide
format check fails on 24 preexisting files** (notebooks, old scripts/docs and the
untracked legacy DNS package); SHA checks confirm none changed this run. It is
not reported as a global Format PASS and unrelated files were not reformatted.

ML initial collection under the SOC interpreter failed for missing pandas.
A subsequent demo-environment run had 259 passes / one environment-isolation
failure because its path includes the SOC repo; an ML-interpreter run passed
260 tests, then 262 after two new manifest/source-identity tests were added.
No failed test was weakened or skipped to obtain the final pass.

Selected SOC changes are exactly:

- `docs/linux-soc-v1/verified-producer-retraining.md`
- `docs/linux-soc-v1/verified-producer-contracts.json`
- `docs/linux-soc-v1/verified-producer-evidence.json`
- `tests/unit/operational_features/test_retraining_readiness.py`

ML has 11 selected files: five pure producer/admission source files, two test
modules, one synthetic hand-reference JSON and three documentation/evidence files.
The ML report lists them. No runtime source, existing artifact or unrelated Stage
content is selected. All 1,023 existing SOC files and 444 existing ML files in the
initial tracked/untracked inventory remain SHA-identical; seven separately hashed
legacy artifact/resource files also match. Large raw/processed datasets were not
hashed in full and no whole-corpus integrity claim is made.

Independent SOC HEAD export + the four selected files: **762 passed, 0 failed
(228.04s)**. The guard blocked one attempted socket creation; no native capture,
traffic or actual LLM request occurred. Export Ruff passes; 836 files format-clean.
Its behavior tests do not import ML, Replay or any excluded user changes.
Only documentation ledger text was finalized after that run; tested Python and
contract/evidence SHA values remain identical. New ML tests also pass from their
separate export, with no runtime gate change. Selected files are eligible for the
requested preparation commits; unrelated ML global formatting remains unresolved.
