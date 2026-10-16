# Final E2E demonstration and post-outage evidence recovery

## 1. Objective and final verdict

**PARTIAL after the outage.** The repository retains all 20 captured GUI
images, the original summarized evidence manifest and the actual-model
rehearsal tests. Image integrity, reviewed artifact SHA values, replay source
identities and Producer contract can be checked now. The temporary primary
receipts, Authentication DBs, research audit DB, checkpoints and original
test/crash logs are MISSING, so their digests cannot be independently
recomputed now. No missing evidence was replaced or recaptured.

The collection run's VERIFIED result remains historical. It is not an
unqualified post-outage verification or production readiness claim.
SIGILL root cause remains unknown. The next phase is final reporting and
portfolio work, with these limitations disclosed; no new AI/Runtime/GUI
features were added during finalization.

## 2. Architecture and security model

```text
Existing offline PCAP replay → Network Producer 1.1.0 → isolated Quality/Edge worker
Existing precomputed DNS9 fixture → verified DNS native worker
                                          ↓
                                Research receipt / advisory
                                          ↓
                         Existing READ-only Orchestrator / checkpoint
                                          ↓
                              Existing Tkinter Command Center

Retained NATIVE_OS Authentication → existing Source / Queue / Investigation
```

The domains retain different source identities. Model output is advisory,
not observed fact. Authentication was not combined with Network/DNS into a
fabricated live attack. Existing policy, approval, provenance, audit and
WRITE_DENIED boundaries were preserved. Operational Network/DNS remains
BLOCKED / NOT_INFERABLE. No new capture, journal collection, model training,
external test traffic, model promotion or OS security WRITE was performed
during recovery finalization.

## 3. Environment and run identity

| Item | Collected value |
|---|---|
| Collection run | `4640687a-bbd7-47eb-8cc4-c82f6a6f6157` |
| Collection validation UTC | `2026-10-16T01:14:25.012250+00:00` |
| SOC source HEAD | `3704814fd6c888369af9a55aa919060878aacb73` |
| ML source HEAD | `e1a01260f0463a38d4d778859bc2a86f8e9cfbde` |
| OS / kernel | Ubuntu 24.04.4 / `6.18.33.2-microsoft-standard-WSL2` |
| GUI | Python 3.12.14, Tk 9.0, Tcl 9.0.4, WSLg 1.0.73.2 |
| Native dependencies | numpy 2.5.3, sklearn 1.9.1, joblib 1.6.0, LiteRT 2.3.0 |
| WSL application version | UNKNOWN |

The separate post-outage run ID and timestamp are in
[recovery-verification.json](recovery-verification.json). No new native calls
were added to the original run. Original manifest bytes are preserved at
[history/evidence-manifest-collected.json](history/evidence-manifest-collected.json),
file SHA256 `d8546713be92a468aa716cd01c5f0070fe71e02fe02d53c69dd3ed3c43ec7963`,
canonical digest `a31dc1dc67399ce4548c2a724cee58899330b1a8037168288705e8255a138a3b`.
The final [manifest](evidence-manifest.json) preserves its run, date, six
invocations, screenshots and recovery data, adding only known limitations
and a new explicit canonical seal. A seal detects changes; it is not an
independent signature authenticating a missing primary receipt.

## 4. Network Quality / Edge

The existing actual RandomForest and Scaler + LogisticRegression ran twice
each on verified OFFLINE_PCAP-derived flows. Producer 1.1.0 / Network14 /
float32 was preserved. The inputs are selected training-session replay
samples; these results do not measure holdout accuracy or live detection.

| Model | Scores | Threshold | Prediction | Recorded latency ms |
|---|---|---|---|---|
| Quality | 0.0; 1.0 | 0.35 | CLASS_0; CLASS_1 | 10.601629; 10.254169 |
| Edge | 0.000242733833; 0.999817192554 | 0.8 | CLASS_0; CLASS_1 | 6.743938; 7.047029 |

Artifact SHA256, rechecked after the outage without loading models:

- Quality: `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603`
- Edge: `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882`

Feature contract digest:
`84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e`.
Producer configuration:
`7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7`.
The existing raw PCAP and label file SHA were rechecked and the four Network
manifest entries matched the committed replay catalogue's source, feature
and input digest triples. This does not reconstruct the missing receipts.

## 5. DNS Security

The actual LiteRT INT8 model ran twice on the existing DNS9 Native Fixtures.
Scores 0.55859375 / 0.0; threshold 0.5 (existing detector default, unvalidated);
CLASS_1 / CLASS_0; recorded native latency 19.331278 / 17.203753 ms.
Network and DNS latency fields have different instrumentation scopes and
are not a controlled cross-model benchmark.

- Model SHA256: `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33`
- Scaler SHA256: `2735f7650a7d7888ee68f2df870b4e29d83666962931ae2aecb9aa339f40266a`
- DNS9 contract: `3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0`

Both artifacts still match. Fixture input digests match the existing DNS
catalogue. Original DNS training producer, DNN training/export provenance,
calibration and operational raw-FQDN parity remain UNVERIFIED. DNS7 was not
substituted. Fixture inference is not real DNS attack detection.

## 6. Authentication retained evidence

The historical run read the existing retained NATIVE_OS stores without a
new journald collector: 560 retained queue records, one accepted
Authentication event, one window, one DONE_READ_ONLY finding, queue backlog
0. Unsupported retained logs are not counted as Authentication attacks.
Original event timestamp was `2026-08-28T00:23:24.127892+00:00`.
Runtime STOPPED / DEGRADED / NOT_READY, collector checkpoint RESUMED_EXACT.

Four SQLite integrity checks were `ok`; the four before/after DB SHA values
were identical in the collected manifest. Provenance and audit references
were validated then. Those temporary databases are now MISSING. Historical
hash equality is preserved, but current DB integrity and unchanged SHA
cannot be claimed. Other persistent scenario stores were not substituted.

## 7. Investigation

Six native invocations have six distinct READ-only investigation references,
each ASSESSED_READ_ONLY, checkpoint restored and `provider_calls=0`.
The existing Orchestrator used SCRIPTED_OFFLINE_RESEARCH, not a live cloud
LLM. Context digest, model/receipt identity and evidence reference remain
in the manifest. The current integrity tests reject incident merging,
operational promotion, nonzero provider calls and invalid checkpoint claims.
They validate the surviving summary, not the missing checkpoint bytes.

## 8. Audit / recovery

Historical research audit: 12 events, SQLite `ok`, audit chain VERIFIED,
head `811d3d38be19b418d04dd5855f8b07c2d7c24ed507b30443483c16a2c817259d`.
GUI reopened in a **new Python process**, restored the same six invocation
IDs and audit head, reused cached replay with zero new native calls, and
recorded STOPPED / no active worker. The first process's worker was closed.
This is historical process restart recovery, not proof of exactly-once
external effects or persistence through server loss.

After the outage the primary audit DB, full receipts and checkpoints are
MISSING from their former temporary workspaces. Current revalidation of
those stores is BLOCKED. The stored summary and screenshot hashes passed;
no new replay was used to manufacture replacements.

## 9. GUI and screenshot review

All **20 original actual WSLg PNGs** survived; their SHA256, PNG headers,
dimensions, coverage and path safety were rechecked. All 20 were visually
reviewed, with no new captures, retouching, raw payload or personal path
disclosure. Original collection provenance is retained; post-outage pixel
inspection alone cannot independently attest the capture mechanism.

| View | Captures |
|---|---|
| Initial Dashboard | [1920](screenshots/dashboard-initial-1920.png), [1366](screenshots/dashboard-initial-1366.png) |
| Quality | [1920](screenshots/network-quality-1920.png), [1366](screenshots/network-quality-1366.png) |
| Edge | [1920](screenshots/network-edge-1920.png), [1366](screenshots/network-edge-1366.png) |
| DNS | [1920](screenshots/dns-security-1920.png), [1366](screenshots/dns-security-1366.png) |
| Authentication | [1920](screenshots/authentication-1920.png), [1366](screenshots/authentication-1366.png) |
| Investigation | [1920](screenshots/investigation-1920.png), [1366](screenshots/investigation-1366.png) |
| Audit | [1920](screenshots/audit-1920.png), [1366](screenshots/audit-1366.png) |
| Restart | [1920](screenshots/runtime-recovery-1920.png), [1366](screenshots/runtime-recovery-1366.png) |
| Unified Dashboard | [1920](screenshots/unified-dashboard-1920.png), [1366](screenshots/unified-dashboard-1366.png), [1280](screenshots/unified-dashboard-1280.png) |
| Exact CLI mapped window | [1600](screenshots/one-command-1600.png) |

The exact CLI case mapped a window and registered graceful shutdown after
2.563733 seconds; backend data-ready latency is UNKNOWN. Its early screenshot
is still CHECKING with an empty body and is not proof of populated Dashboard.
The separate Dashboard captures show populated status and zero initial calls.

Charts show actual recorded 2→6 packets across two offline flows, DNS
0.5586→0.0, six invocation timestamps and recorded latency. They are not
live traffic or calibrated threat probability. At 1366×768 lower cards and
some result rows require scrolling; the Edge result is visible in its 1920
capture. Recovery snapshots retain WAITING progress text while the historical
backend check recorded STOPPED/no worker; Unified 1366 shows WORKING during
refresh. These are disclosed state-display limitations, not retouched results.

## 10. Security and preservation

No product source, dependencies, artifacts, producer contracts or operational
gates were modified. This task adds only rehearsal/integrity tests and public
evidence/documentation. Existing user changes and Reliability Replay are
excluded from the commit and independent export. The post-outage baseline
contained 118 unrelated SOC files and 10 ML files; their SHA preservation
is checked against a private audit inventory. A missing pre-outage private
inventory cannot establish every file's equality across the outage itself.
Reviewed model and replay raw identities are independently matched to pins.

## 11. Tests and independent export

Historical results supplied with the recovery task (not rerun or added to
current totals):

| Run | Previous result | Primary log now |
|---|---|---|
| Runtime | 266 passed | MISSING |
| Core / Self-Improvement | 491 passed | MISSING |
| Governance / GUI / Model | 351 passed, 1 deselected | MISSING |
| Evidence Manifest | 27 passed | MISSING |
| Final fresh-process actual-model GUI rehearsal | 2 passed, 50.15 s, as recorded before outage | MISSING |
| Interrupted same-process rehearsal | SIGILL, no final passing result | MISSING |

The deselected case was an unbound INET socket identity-denial fixture
incompatible with the no-network test guard; it is not counted as passed.
The interrupted run is never counted as success. Prior screenshot QA runs
are separate from the final collection run.

Current evidence-only test results, lint/format/diff checks, source export
verification and preservation outcome are recorded in
[recovery-verification.json](recovery-verification.json). The first current
run passed the original 27 cases. Finalization adds immutable-history and
cross-run/missing-evidence checks. No long regression, native inference or
GUI replay was repeated because product code, dependencies and artifacts
did not change and the missing primary evidence is explicitly disclosed.

The independent export must contain SOC HEAD plus only the final-demo
allowlist. It checks public manifest, all images, history, source catalogue
identity, documentation links and focused tests without user/Replay files.
External artifact references are checked at their existing trusted locations;
binaries are not copied or deserialized. Full native inference and pixel
identity replay are outside this recovery export's verified scope.

## 12. SIGILL known issue

Status: **ROOT_CAUSE_UNKNOWN / RECOVERY_VERIFIED / RECURRENCE_NOT_EXCLUDED**.
One prior in-process multi-window rehearsal exited with signal SIGILL (-4)
after its first case. Exact failure timestamp and faulting native extension
are UNKNOWN. The original crash log is MISSING after the outage; the following
is a qualified summary of the earlier captured trace, not a newly recovered log.

Python 3.12.14 reported “Illegal instruction”; a thread was garbage collecting
with a stack through `realtime/models.py:identities`, Pydantic JSON validation,
queue decode, Authentication view, GUI queries and a concurrent-futures worker.
Other backend event-loop threads were present; many native extensions were
loaded. This does not establish that GC, Tk, numpy or any particular library
caused the illegal instruction. No native fault address/core diagnosis exists.

The harness was changed to reopen in a fresh Python process, matching the
real CLI lifecycle, and release Tk cycles on the creating thread. The later
two-case run passed with six actual inferences and 20 screenshots. No product
fix was inferred from that recovery. No SIGILL reproduction was attempted
after the outage. Recurrence remains possible.

## 13. Remaining limitations and next decision

- Primary temporary evidence and prior logs are unavailable; public summary
  verification does not replace fresh SQLite/audit/receipt digest validation.
- A trusted backup matching the recorded DB/receipt identities would permit
  further read-only recovery validation. Do not substitute a new run under
  the original Run ID. Future evidence should use durable private storage.
- SIGILL root cause and the disclosed transient GUI progress labels remain.
- DNS producer parity, Network live producer equivalence, production model
  readiness, live LLM assessment and physical Linux validation are unverified.
- Research integration demonstration is complete historically; production
  Network/DNS inference and automatic response are not enabled.

Use [reproduction-guide.md](reproduction-guide.md) for the supported GUI flow.
Present the surviving images and measured research outputs with these limits.
No additional feature development was performed or is required by this report.
