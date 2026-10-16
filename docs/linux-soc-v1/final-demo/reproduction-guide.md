# Final research demonstration: reproduction guide

This guide describes the existing GUI. The collection run was
`4640687a-bbd7-47eb-8cc4-c82f6a6f6157`, completed at
`2026-10-16T01:14:25.012250+00:00`. Post-outage evidence verification is a
separate run in [recovery-verification.json](recovery-verification.json).
See the [final report](final-e2e-report.md) before presenting these results.

## Required environment and packages

The collected environment was Ubuntu 24.04.4 / WSL2, kernel
`6.18.33.2-microsoft-standard-WSL2`, WSLg 1.0.73.2, Python 3.12.14,
Tkinter/Tk 9.0 and Tcl 9.0.4. SOC and ML package versions were 0.1.0.
WSL application version is UNKNOWN. This is not physical Linux validation.

Use the existing SOC `.venv` and the project-isolated
`.security-ai-demo/inference/bin/python`. The collected native environment
had numpy 2.5.3, scikit-learn 1.9.1, joblib 1.6.0 and ai-edge-litert 2.3.0.
Do not install, upgrade or copy models to reproduce a screenshot. Missing
dependencies or a digest mismatch must remain a visible error.

## Model artifact identity

`$SOC` and `$ML` below denote the two project roots, not literal directories.
The complete reviewed paths, sizes and SHA256 values are in
[evidence-manifest.json](evidence-manifest.json), `environment.artifacts`.

| Model | Existing location | Identity |
|---|---|---|
| Quality RandomForest | `$ML/models/network-research-v1-final/quality_rf/model.joblib` | `linux-network14-research-v1-quality_rf` |
| Edge Scaler + LogisticRegression | `$ML/models/network-research-v1-final/edge_lr/model.joblib` | `linux-network14-research-v1-edge_lr` |
| DNS LiteRT INT8 | `$SOC/.security-ai-demo/artifacts/dns/model/dnn_int8.tflite` | `dns_cicbell_dnn_int8` |
| DNS StandardScaler | `$SOC/.security-ai-demo/artifacts/dns/preprocessor/scaler.joblib` | Pinned DNS9 preprocessor |

The Network demo additionally requires the existing IoT-23 8-1 PCAP and label
files referenced by `src/soc_agent/security_ai/research/replay.json`. They are
not bundled here. Network14 uses Producer 1.1.0, float32, 14 ordered features.
DNS9 uses precomputed fixture values; its original training producer and
calibration are UNVERIFIED. DNS7 is not substituted for DNS9.

## GUI launch and model check

```bash
cd ~/kdt-linux/autonomous-soc-agent
.venv/bin/python -m soc_agent.gui
```

Wait for the read-only environment check to complete. Launch must not start
research inference or collectors. An unavailable runtime is OFFLINE/STOPPED,
not LIVE. READY on the fixture environment means replay readiness, not
operational readiness. Operational Network/DNS must remain BLOCKED /
NOT_INFERABLE. The initial one-command screenshot captures a mapped window
during CHECKING; its timing is not backend data-ready latency.

## Network research demo

Open **Research Demo** or **Open Research Demo** from Dashboard. Select
**Network · Quality**, input **1**, then **Run Demo**. After completion,
select input **3** and run once. Repeat with **Network · Edge**. The existing
Run Demo action prepares the session; no JSON editing or extra terminal is
needed. Check the visible OFFLINE_PCAP / RESEARCH_ONLY source label first.

In a fresh research workspace, the collected result was two confirmed calls
per Network model. The offline flow plot had observed packet counts 2 and 6.
These selected training flows demonstrate integration; they are not a
holdout accuracy measurement or live traffic trend. Replaying a completed
input in the same workspace should reuse its receipt, not add a native call.

## DNS research demo

Select **DNS · Security**, input **1**, **Run Demo**, then input **2** and run.
The source must read FIXTURE / precomputed DNS9 / producer parity UNVERIFIED.
The collected scores were 0.55859375 and 0.0 with the existing unvalidated
threshold 0.5. They are uncalibrated model outputs, not verified attack
probabilities. No real DNS query is converted or captured by this demo.

## Authentication retained evidence

Use Dashboard **Connect** to select an already retained Authentication runtime
directory containing its complete Source/Queue/Monitor/Audit stores. Do not
use Initialize or Start Runtime for this retained-evidence demonstration.
Open **Investigations** and select the NATIVE_OS finding. Read its original
timestamp and READ_ONLY status. It must not be presented as a current event.

**Post-outage limitation:** the collection run's four Authentication DBs were
in a temporary workspace that is now MISSING. The screenshots and original
before/after SHA summaries survive, but the exact DB cannot currently be
reattached or revalidated. An unrelated scenario database is not a substitute.
Restoring a trusted backup with matching SHA would be needed to reproduce
that retained record. Do not generate new journal events to fill the gap.

## Investigation and audit

In Research Demo select a result and choose **Investigation**, then
**Audit / receipt**. Check the separate Incident ID, input source, model
identity, receipt binding, ASSESSED_READ_ONLY status, checkpoint and audit
integrity. Scroll to the detail cards on smaller windows. Technical JSON and
full IDs are in the existing collapsed detail controls.

The recorded investigation used the existing Orchestrator with
SCRIPTED_OFFLINE_RESEARCH (`provider_calls=0`). This demonstrates guarded
investigation integration, not a live cloud LLM assessment. Model output
remains advisory and is not promoted to observed fact or operational finding.

## Stop, reopen and recovery

Choose **Stop research**, close the GUI normally and relaunch the same command
as a new Python process, with the same GUI data directory. The default GUI
data is under the user's local application data directory (or XDG_DATA_HOME).
Stored receipts should reappear with idle workers; rerunning a cached input
should not increase confirmed inference counts. Retained Runtime stays STOPPED.

The recorded automated rehearsal used isolated XDG storage and a separate
process for reopening, matching the real CLI lifecycle. Those temporary
receipts, checkpoints and research audit DB did not survive the outage.
Recovery is therefore a historical verified result, not newly demonstrated
post-outage recovery of those missing databases.

## Evidence-only verification

This command verifies surviving public evidence and rejection cases without
model loading, GUI execution, network traffic or capture:

```bash
.venv/bin/python -m pytest --import-mode=importlib -q tests/unit/final_demo
```

`tests/gui_final_demo_checks.py` is an explicit actual-model rehearsal harness,
not part of this evidence-only command. It requires private isolated output,
the existing trusted artifacts and the complete retained Authentication
workspace. It was not rerun after the outage. Missing evidence must not be
silently replaced with fixtures.

## Known issues and expected boundaries

One pre-outage rehearsal exited with SIGILL. ROOT_CAUSE_UNKNOWN,
RECOVERY_VERIFIED in a fresh process, RECURRENCE_NOT_EXCLUDED. The original
crash log is MISSING; no library or GC root cause has been established.

At 1366×768 lower cards and some result rows require scrolling. Recovery
screenshots retain WAITING progress text although the historical backend
assertion recorded STOPPED with no active worker; one Dashboard screenshot
shows WORKING during refresh. Screenshots are snapshots, not lifecycle traces.
No screenshot has been retouched to claim a different state.

Expected boundaries remain RESEARCH_ONLY, BLOCKED, NOT_INFERABLE,
WRITE_DENIED, no automatic promotion and no actual security response.
