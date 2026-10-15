# Raw dataset acquisition, fallback and SOC readiness

Date: 2026-10-15 / WSL2 Ubuntu. Baselines:
SOC `5ed566987d6d03dd6ae8c60d3cf2521da0734990`;
ML `e564499ffc8cb7682e03876fde82892db89a1305`.

**Overall: PARTIAL preparation; actual dataset admission and all model retraining
readiness are BLOCKED.** No raw corpus transfer, training or artifact creation has
occurred. Official metadata/file identities and bounded validation contracts are
verified as described below. No operating inference gate is opened.

Detailed ML report: sibling repository `docs/raw-dataset-acquisition.md`.
Portable evidence: [pending manifests](raw-dataset-manifests.json),
[exact Network download plan](raw-acquisition-download-plan.json).
The snapshots are byte-identical across repositories and carry no runtime authority.

## 1. Baseline and ownership

Both HEADs match the supplied baselines; indexes were initially empty. Eight tracked
SOC user modifications and all untracked Replay/other outputs are preserved.
ML's untracked legacy DNS package remains excluded. Neither repository's existing
model/scaler, Producer v1.0.0, original Golden fixtures, pyproject, GUI/runtime,
Policy/Approval nor operational/synthetic provenance contracts are changed.

The previous audit's local data shortage was not treated as a reason to retrain on
precomputed CSVs. This task queried live official file metadata and selected
concrete fallback files while keeping acquisition distinct from admission.

## 2. Existing dataset acquisition status

| Dataset | Current evidence | State |
|---|---|---|
| CSE-CIC-IDS2018 | Public S3 listing succeeds: ten capture-date folders, nine PCAP ZIPs and one PCAP RAR, plus logs | ACQUISITION_READY, not ADMITTED |
| CIC-Bell-DNS-EXF-2021 | Official download route is a registration form reporting server error, without verified file list | INSUFFICIENT_EVIDENCE |

[Official CSE page](https://www.unb.ca/cic/datasets/ids-2018.html) supplies acquisition,
labeling context and attribution conditions. Actual bounded [S3 index queries](https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&delimiter=%2F&max-keys=40)
verified object names/sizes/modification IDs; all ten date listings are untruncated.
For example 2018-02-14 `pcap.zip` is **39,913,353,098 bytes**. The full per-date file
inventory is in the JSON and ML report. No ZIP member lists or expanded lengths
were obtained; RAR support is absent. Raw SHA256 and raw↔label joins are UNKNOWN.
ETags are not converted to SHA256. Existing flow CSVs do not reconstruct packets.
Schedule, NAT, timezone and old flow-boundary mapping still require review.

[Official DNS-EXF page](https://www.unb.ca/cic/datasets/dns-exf-2021.html) documents
the corpus and citation terms, but its actual
[download form](https://cicresearch.ca/CICDataset/CICBellEXFDNS2021/) did not expose
files. No registration data was submitted and no access boundary was bypassed.
An introductory page or historical redirect to a generic index was not accepted
as raw availability. No raw DNS query/label pair was acquired.

## 3. Fallback comparison (three shortlisted candidates)

| Candidate | Verified file / terms evidence | Limitation | Selection |
|---|---|---|---|
| CTU-13 Scenario 7 | Live HTTPS header-PCAP / bidirectional-label objects; official CC-BY attribution | Unknown Background/To-Botnet labels; header-only importer and offline Producer origin absent; one session | Network raw/label binding pilot, ACQUISITION_READY |
| DomainRadar 2024 v1 | Official Zenodo export has file identities/checksums/license; selected file HEADs succeed, CC-BY-4.0 | Domain reputation categories differ from exfiltration/query labels; bytes/PSL/grouping not checked | DNS acquisition candidate, ACQUISITION_READY |
| UMUDGA v1 | Dataset/author source reports raw DGA lists, MIT | Individual raw-file sizes/list not verified; generated DGA domains differ from observed DNS | INSUFFICIENT_EVIDENCE, not selected |

Sources: [CTU overview](https://www.stratosphereips.org/datasets-overview),
[Scenario 7 files](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/),
[DomainRadar metadata](https://zenodo.org/records/13330074/export/json),
[UMUDGA record](https://data.mendeley.com/datasets/y8ph45msv8/1).
The published checksums in CTU malware descriptions identify an executable, not
the packet capture. No malware executable or payload archive was downloaded.
CIC-IDS2017 and UNSW-NB15 were screened but not shortlisted: the observed official
routes require registration/server recovery or authentication rather than offering
a verified individual raw-file list. No uncertain mirror replaced them.

## 4. Exact storage and approval boundary

The pending Network plan names exactly two HTTPS files:

- Header-only `capture20110816-2.truncated.pcap.bz2`: **111,664,996 bytes**.
- Detailed `capture20110816-2.binetflow`: **15,630,512 bytes**.

Total **127,295,508 bytes (~121.4MiB)**, separate ignored ML path
`data/raw/acquisition/ctu13-s07-header-pilot-v1`. Limits: two files, 256MiB download,
512MiB expansion, no automatic retries and a 300s per-file caller watchdog.
The explicit approval question remains pending. No raw download was started;
elapsed time is not approval. Storage will not overwrite existing data.

The DNS `malware.json` + `benign_umbrella.json` pair requires **7,157,184,952 bytes**
and a separate download/storage/privacy decision. License and MD5 identities were
confirmed in the official export; local SHA256 is UNKNOWN. Enrichment fields may
contain WHOIS/contact details, so a future bounded importer must retain only
required domain/source/label/time linkage. The Network approval question does not
authorize DNS downloads. Do not contact the listed domains or execute dataset code.

ML's new storage helper is opt-in, validates exact HTTPS host/URL, rejects redirects,
checks size/type/prefix, calculates SHA and publishes without clobbering old files.
Missing MIME remains UNKNOWN and requires explicit review plus format validation.
ZIP/bzip2 checks bound expansion and reject traversal/symlinks/special members,
truncation and concatenated data. ZIP contents are not extracted. The transfer
helper has socket/body timeouts; a hard 300s process watchdog must be supplied by
the approved caller before use. It is not automatically run by status queries.
Only local synthetic bytes/archives were used in its tests.

## 5. Producer compatibility and required separate decision

**Network v1.0.0 does not accept OFFLINE_PCAP.** Its allowed origins are
NATIVE_AF_PACKET and EXPLICIT_PACKET_FIXTURE. Public PCAP cannot be called either
to force the existing function to accept it. New binding tests verify rejection;
no producer code/config/Golden identity was modified or bypassed.

A Network **v1.1.0 proposal only** would add explicit offline-file/session lineage
and header-only capture-quality semantics while retaining the 14 numerical
features where valid. It needs separate approval, independent reference tests,
new configuration/feature binding review and compatible model training. Download
approval is not Producer-change approval. CTU truncated headers also need a
reviewed offline reader; existing complete-packet parsing must not receive padded
or guessed payload. No reader or version change is implemented here.

DNS v1.0.0 accepts RAW_LABELED_FQDN; DomainRadar's declared `domain_name` field is a
candidate lexical input for its seven float32 features. Actual rows, invalid-name
exclusions and source/category linkage are not verified. Raw domain lists cannot
prove DNS request timestamps or exfiltration. Registered-domain/campaign grouping
requires a pinned PSL/mapping; taking the last two labels is not accepted.
The new DNS model's task scope must be reviewed if switching to reputation labels.

## 6. Binding, split, manifests and admission

ML pure predicates reuse current Producer validation and return external label
references. They reject unmatched/unknown/ambiguous Network interval/tuple/session
matches, and duplicate/conflicting normalized DNS labels. Nothing defaults to
normal. Tests use independently assigned Fixture labels only, not model outputs.
No public raw↔label join has passed and no positive admission is certified.

Split validation checks supplied raw/bound-feature digests, explicit groups, class
support in three splits and chronological nonoverlap. A single CTU session cannot
establish independent three-way capture holdout. Actual domain/campaign and clock
mapping remain unverified; declared groups alone cannot prove independence. No
actual train/validation/test split or External Holdout is frozen. Test data must
not tune features, models or thresholds.

All five pending manifests include version/license/source/raw/label identities,
Producer/config/feature-contract digest and UNKNOWN byte/sample/split metrics.
Their digest checks reject tampering. Even a rehashed pending manifest cannot
claim ADMITTED, acquired counts, training or WRITE authority. This is a
**pending-only contract**, not a completed positive Dataset Admission engine.
No model or LLM result is reused as ground truth. Raw files are not committed.

## 7. Model readiness and future training plan

| Model | Dataset admission | Producer / actual Golden / independent split | Readiness |
|---|---|---|---|
| Network Quality | NOT_ADMITTED | offline origin/import blocker; real checks NOT RUN | BLOCKED |
| Network Edge | NOT_ADMITTED | same input blocker; separate future artifact validation | BLOCKED |
| DNS Security | NOT_ADMITTED | lexical fit reported only; real checks NOT RUN | BLOCKED |

Existing synthetic reference tests are preserved and pass, but they are not
Golden pairs for any acquired corpus. Actual class/exclusion counts and dataset
SHA are UNKNOWN. No training metrics, latency/RSS or artifact SHA was invented.

Required decisions: approve the exact Network pilot (or decline it); separately
review a v1.1 offline source contract; choose DNS domain-reputation fallback with
its 7.16GB/privacy budget or obtain original exfiltration raw files manually.
Then verify bytes, joins and actual Golden cases; acquire independent sessions /
source/time groups, freeze holdout and manifest, and request separate training
approval. Future training must record seeds/library/hyperparameter/dataset identities,
training-only preprocessing and independent metrics, without comparing different
task/input contracts as if they were the same benchmark. Physical Linux and
operational gate release remain later work. No automatic retraining is wired.

## 8. Tests, export and change scope

New ML tests use fake responses/local archives and explicit Fixture labels to
exercise integrity, no overwrite, host/path/type/size/timeout, archive safety,
source tampering, origin rejection, ambiguous labels, grouping/time leakage and
pending-manifest promotion denial. SOC tests verify copied evidence digests,
UNKNOWN/no-data assertions and the three independent closed runtime gates.
Related existing Producer/package/runtime/approval/source/provenance/GUI tests are
reused. The existing audit-hook guard blocks real AF_PACKET/INET sockets during
SOC tests; no real API/capture is required. Per-run totals follow after completion.

Selected SOC files only: this report, `raw-dataset-manifests.json`,
`raw-acquisition-download-plan.json` and
`tests/unit/operational_features/test_raw_acquisition_readiness.py`.
ML changes are four small offline source modules, three test modules and three
report/metadata/plan files. Existing runtime/GUI, Producer v1, models, source store,
Synthetic v2, Operational Provenance v3, NOT_INFERABLE and WRITE_DENIED remain.
Replay/user changes are excluded from independent exports and selected commits.

CSE-CIC-IDS2018 remains the primary existing Network training-data candidate.
Selecting the smaller CTU files is a proposed binding-feasibility pilot, not an
automatic training-corpus replacement or a claim that CSE acquisition is impossible.
A full dataset switch would follow actual binding/holdout review and a separate
decision. The pending approval covers only this pilot's two named files.

## 9. Executed validation ledger

| Execution | Result |
|---|---|
| New SOC acquisition/readiness tests | 6 passed, 0 failed (0.31s), included below |
| Working SOC related regression | 768 passed, 0 failed (295.59s) |
| Final ML acquisition + Producer + legacy package/benchmark regression | 328 passed, 0 failed (22.01s) |
| Final independent ML HEAD export + ten selected files, acquisition/Producer tests | 132 passed, 0 failed (0.21s) |

These are per-execution results, not cumulative counts. Earlier development runs
preceded the central-directory-allocation guard test; they are not substituted for
the final tested source. All dataset acquisition tests use local synthetic bytes
and labels. The working SOC guard blocked one socket-creation attempt; no real
capture/traffic was generated. Real LLM requests are disabled. The unrelated
untracked `test_producer_parity_boundary.py` is excluded in both SOC test trees.

SOC full Ruff/Format and Git whitespace checks pass. ML `ruff check src tests` and
all seven new Python files' Format checks pass; the independent ML export also
passes those checks. ML full Format still reports **24 preexisting files** (old
notebooks/docs/scripts and the preserved untracked legacy DNS package); none are
silently reformatted or reported as a global PASS. Both repository indexes were
untouched before selective staging. No new dependency/environment install occurred.

Initial SHA inventories cover 1,027 existing SOC files and 455 ML files. All remain
identical. Seven separately hashed legacy model/scaler/resource files also match
the existing evidence manifest. Whole old raw/processed datasets were not hashed;
no whole-corpus integrity claim is made. New raw storage paths do not exist.
Independent SOC export results follow after completion.

Final independent SOC HEAD export plus the four selected files: **768 passed,
0 failed (373.88s)**. One socket attempt was blocked by the guard; no native
capture/traffic or real LLM call occurred. Export Ruff passes and 838 files are
format-clean. Its source/tests/metadata do not require uncommitted Replay or ML
source. Final source/metadata/evidence SHA values match the tested export; only
report ledger paragraphs were finalized afterward. Approval is still pending,
so selected commits record acquisition readiness, not an acquired dataset.
