# Original Gate C — Common Real-Time Pipeline

2026-10-13. **GATE_C_REALTIME_INCONCLUSIVE** for the complete supported-platform scope.
Implemented and exercised scope: Windows 11 System metadata and WSL Ubuntu journald,
common queue/worker and existing actual SOC runtime. Separate Linux Desktop/Headless hosts
and live Network/DNS feature derivation remain unverified. No mandatory path failure remains
in the exercised scope; incomplete verification is not reported as a failure.

## Baseline / inventory

Preserved baseline commits: Gate B `787dff886c203cd14e351021f7d72b08fae17147`,
SOC Integration `b47c83d3e563a5c0862cc56edb21c504440e7724`, Platform Validation
`0bd5e5d234cef9f49514a79bc48ea0ffa36aad8f`. Their tags were not changed.
The previous named Gate C/D reports are prerequisites, not proof of this real-time Gate C.
Before implementation, only bounded local JSONL replay existed; no OS collector/queue existed.

| Requirement | Implementation / new evidence |
|---|---|
| Common Event Contract | models.py: strict versioned source identities, UTC and original timestamp, source digest, optional existing typed features; unit rejection/round-trip/dedup tests |
| Windows collector | collectors.py: native Get-WinEvent, allowlisted channels, metadata-only projection, record/cursor continuity; actual System CLI restart PASS |
| Linux collector | collectors.py: journalctl selected fields, first +N ordering, cursor retention probe, explicit missing journald rejection; actual WSL CLI restart PASS |
| Ingestion Queue | queue.py: private real SQLite, bounded active/retained records, atomic enqueue+cursor, token claims/retry/poison, integrity checking |
| Inference Worker | worker.py: no filling; reviewed official feature identity/finite values; official 3 predictors through existing service; typed context/actual SOC Runtime |
| Failure/restart | real hard-exit claim recovery, commit failure rollback, ack-loss replay, stale token rejection, source/cursor corruption and retry exhaustion tested |
| Existing runtime / governance | shared actual composition; source-only READ tool, no human authority or WRITE handler; protected external context, human boundary, checkpoint/receipt reuse |

## Executed evidence

Logs are outside versioned deliverables; no full suite was repeated.

| Command / evidence | Result |
|---|---|
| WSL new unit+integration `tests/unit/realtime tests/integration/realtime` | **18 passed**, 15.23 s, `/tmp/realtime-final-complete.log` |
| WSL direct related queue/runtime-lock/external-runtime regression | **113 passed**, 123.67 s, `/tmp/realtime-regression.log`; earlier snapshot, subsequent changed tests rerun |
| WSL final queue/runtime failure subset | **16 passed**, `/tmp/realtime-final-affected-linux.log` |
| WSL official 3-model context / explicit actual Runtime restore | **1 passed**, `/tmp/realtime-native-resume.log`; subsequently included in 18-test run |
| Windows native initial new queue/runtime | **9 passed**, 11.21 s; earlier snapshot |
| Windows new tests + existing cross-platform runtime-lock | **29 passed**, 84.79 s, `%TEMP%\soc-realtime-native-final-20261013.log` |
| Windows changed queue/runtime/injection/failure subset | **16 passed**, 24.09 s, `%TEMP%\soc-realtime-native-affected-20261013.log` |
| Windows final feature preflight / official 3-model actual Resume | See final verification addendum below |
| Final Ruff / format / diff | See final verification addendum below |

Counts overlap and must not be summed. There are no skip/xfail additions. An initial test-file
name collision was a collection error, corrected by naming the new test_realtime_runtime.py;
the subsequent regression completed. Early implementation digest API misuse was fixed.
No existing tests or guards were removed. Historical 3104/25 baseline is retained for unchanged
core code, but is not presented as a full regression of new pipeline modules.

Native OS collection versus inference are separate evidence:
- WSL final SERVER command: DONE **1 -> 2** across two actual processes,
  `/tmp/realtime-linux-final.log`, data `/tmp/soc-realtime-linux-metadata-20261013`.
- Windows 11 final metadata-only Desktop command: DONE **1 -> 2**, `%TEMP%\soc-realtime-native-metadata-collector-20261013.log`,
  data `%LOCALAPPDATA%\AutonomousSOCRealtimeMetadata20261013`.
- Preliminary Windows XML-rendered prototype processed **16 -> 32**; superseded by
  metadata-only Get-WinEvent before finalization to avoid unnecessary EventData capture.
- Both final OS branches explicitly returned **NOT_INFERABLE**, provider calls zero.
- Official Quality LightGBM / Edge DNN FP32 / DNS LiteRT inference used explicit existing
  synthetic Top40/DNS9 fixtures. Context has **3 results / 2 observation identities**,
  preserved managed inference provenance, unchanged context digest after restore and
  zero execution_records. This does not prove live OS events supplied ML features.

Windows native Python was existing Conda soc-windows; models used the existing isolated
native interpreter and pinned private AppData artifacts. Current WSL source was read through
UNC with native Python; NTFS data, Event Log and ACL checks ran natively. Original Windows
repository was not overwritten. An early copy placed eight new files only in the old isolated
validation tree; those are a superseded snapshot, not the authoritative final source.

## Changes / security / next stage

Only new `src/soc_agent/realtime/` (7 files), `tests/unit/realtime/test_pipeline.py`,
`tests/integration/realtime/{test_realtime_runtime,test_inference}.py` and this documentation
folder were created. Existing user changes/untracked files, Gate E report, models, Golden
Fixtures, Selection Digest, Fusion v1, External Context v2, Decision IDs/payload, policies,
approvals, audit chain and secure-storage implementations were preserved. No commit/tag/push.

The isolated CLI has no security WRITE handler or human authority. Actual external inference
still uses existing opaque capability/receipt enforcement. Existing Policy/Approval/Execution
security paths are covered by the directly related runtime regression, not newly invented policy.

Original Gate D development may be proposed after review of this scope. Live risk detection,
separate-host deployment and complete platform acceptance cannot be declared ready. See
remaining-risks.md and queue-recovery.md; no following Gate is started automatically.

## Reproduction

WSL (fresh absolute private data directory; no sudo):

```bash
RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m soc_agent.realtime \
  --source journal --profile SERVER --directory /tmp/soc-realtime-new-validation \
  --batch-size 1 --batches 2 --interval 1
.venv/bin/python -m pytest -q tests/unit/realtime tests/integration/realtime
```

The tests use the existing artifact/native interpreter defaults, or explicit
SOC_EXTERNAL_ARTIFACT_ROOT / SOC_EXTERNAL_INFERENCE_PYTHON variables. No model download occurs.

Windows (after conflict-free source preparation, unchanged Conda/native dependencies):

```powershell
conda activate soc-windows
$env:RUN_LIVE_LLM_TESTS='0'
$env:SOC_EXTERNAL_ARTIFACT_ROOT=Join-Path $env:LOCALAPPDATA 'AutonomousSOCFinalArtifacts20261013'
$env:SOC_EXTERNAL_INFERENCE_PYTHON='C:\soc-native-inference-final-20261013\Scripts\python.exe'
python -m pytest -q --tb=short tests/unit/realtime tests/integration/realtime
python -m soc_agent.realtime --source windows --channel System --batch-size 1 `
  --directory (Join-Path $env:LOCALAPPDATA 'AutonomousSOCRealtimeNewValidation')
# Repeat the identical command to resume; no channel permission changes or elevation.
```

For explicit model replay, supply UTF-8 CommonEvent v1 JSONL with `--source fixture --input`
and explicit `--artifacts --native-python`. Native provenance claims in file input are rejected.
Source hashes are in windows-sync.json; copy only absent files into a fresh validation tree,
keep matching files, stop on differing targets. Existing validation trees may contain the
superseded prototype: do not overwrite those files automatically.

## Final verification addendum

- Windows final official Predictor / Feature preflight / actual protected Resume: **2 passed**,
  46.53 s, `%TEMP%\soc-realtime-native-model-resume-final-20261013.log`.
- Final WSL affected subset: **16 passed**, 3.08 s; new full focused set previously **18 passed**,
  with latest preflight/native Resume included. Subsequent journald availability/error-category
  changes do not alter model evaluation or runtime semantics.
- Ruff `check src tests`: PASS. Format `--check .`: PASS (**698 files**). `git diff --check`: PASS.
- Protected tests/fusion_support.py remains SHA-256
  `e5f9d10f706f71b82e80261f7633a1504e27ba24499be948d04adb6eeb3a21c9`.
- No full WSL/Windows rerun, model/artifact modifications, dependencies, commit, tag, push,
  live provider, security WRITE, operating migration or operating deployment.
