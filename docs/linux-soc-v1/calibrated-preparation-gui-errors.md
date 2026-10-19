# Calibrated preparation failure and GUI error propagation

Validation baseline: SOC `89a7989387519c837c21e3a78b920c6577e17392`,
ML `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`. Date: 2026-10-19.

## Actual evidence and root-cause limits

The default GUI Total Monitoring root contains **8 session directories**,
all legacy sessions, and **no Calibrated v2 session**. Its owner/private-directory
checks pass. The unchanged preparation guard rejects `session-*` count >= 8
with **`STREAM_ARCHIVAL_REQUIRED`**. This occurs before allocating a new session,
checking that session's Headroom/Bundle, creating SQLite, acquiring its writer
lock, or checking its model environment.

The verified blocker for this root is **SESSION_ARCHIVE_LIMIT_REACHED**. Independent
temporary-directory reproduction with eight placeholder sessions confirmed:

| Layer | Before | After |
|---|---|---|
| Raw preparation exception | `STREAM_ARCHIVAL_REQUIRED` | Same; guard unchanged |
| Backend `last_error` | `STREAM_PREPARE_FAILED` | `STREAM_ARCHIVAL_REQUIRED` |
| GUI instructions | Environment unavailable | `STREAM_ARCHIVAL_REQUIRED` |
| Listener | False | False |
| Helper SHA display | UNKNOWN | NOT_PREPARED |
| Copy/authentication | Must remain unavailable | Explicitly guarded |

The actual user's click response and its exception were **not durably retained**:
there is no new session store to audit. We cannot claim an independently saved
exception/Run ID for that click. The current root's deterministic blocker, the
identical Fixture, and the two code defects are verified; historical click
attribution retains this evidence limit. No user GUI process was still running
at inspection, so a historical `--data-directory` override could not be checked
from its command line. A different root would require its own evidence; do not
generalize the default-root result to an unverified override.
Existing Native session UUIDs must not
be presented as an identity for the failed Balanced preparation.

Current read-only checks confirm Headroom PASS, 12 affine CPUs, and the original
Bundle/Helper hashes. All **56 existing SQLite databases** passed integrity checks
using `mode=ro&immutable=1` after checking for sidecars. All **8 monitor audit
chains** verified using the existing digest/sequence rules. New-session SQLite,
runtime lock, and model environment were **not reached by the archive-full path**;
existing integrity alone does not prove a hypothetical new session would succeed.
No store initializer/recovery/migration was run on historical evidence.

## Fix

`LiveView.prepared()` chooses a bounded string in this order:

1. `authentication` (printable, nonempty string, at most 512 characters).
2. `last_error` (reviewed-shape ASCII code, at most 128 characters).
3. `error` (same code constraints).
4. The existing default instruction.

Invalid types, control characters, path-like error strings, and oversized fields
are not rendered. Successful command delivery requires `listener_ready=True`,
a nonempty bounded command/session ID, and a 64-character lowercase SHA256.
Only a valid command enables copying, disables Start, and displays LISTENER READY.
A failed or incomplete response clears command/session state, disables copying,
restores Start, and displays **NOT_PREPARED**, the failure code, and no capture.
Authentication is never requested for that response. No password is collected.

The `started()` callback now honors the observation check's result before calling
authentication. A stale READY callback previously could fail to update the view
but still enter the authentication method. Authentication and copy callbacks now
also verify the accepted current command/session and observation. Existing CLI,
Backend approval, terminal handoff, peer attestation, and approval digests remain
unchanged. The ordinary valid READY path is covered by both existing and new tests.

## Preparation diagnostics and ownership

The Backend preserves explicitly reviewed causes and otherwise classifies by the
controlled preparation stage. Raw exception text/paths are never included.

| Condition | Public code |
|---|---|
| Insufficient calibrated resources | `CALIBRATED_RESOURCE_HEADROOM_REQUIRED` |
| Calibrated Bundle mismatch | `CALIBRATED_HELPER_BUNDLE_MISMATCH` |
| Eight-session ceiling | `STREAM_ARCHIVAL_REQUIRED` |
| Session directory/store I/O or security failure | `STREAM_SESSION_STORAGE_FAILED` |
| Nonblocking writer-lock conflict | `STREAM_RUNTIME_LOCK_CONFLICT` |
| Model environment unavailable | `STREAM_ARTIFACT_ENVIRONMENT_BLOCKED` |
| Unclassified preparation failure | `STREAM_PREPARE_FAILED` |

Example archive-full response:

```json
{
  "status": "BLOCKED",
  "last_error": "STREAM_ARCHIVAL_REQUIRED",
  "listener_ready": false,
  "preparation_phase": "SESSION_ARCHIVE",
  "preparation_audit": "NOT_AVAILABLE_BEFORE_SESSION_STORE"
}
```

A fresh attempt clears prior inactive session/store/demo references and counts.
Failure before allocation must not inherit retained Fixture origin, model counts,
helper metadata, or authority to write a previous session's audit. After this
attempt has acquired its own store writer lock, it records one chained
`STREAM_PREPARATION_FAILED` event containing only `code` and `phase`. Earlier
failures emit a sanitized application warning and explicitly report that a
session audit is unavailable. Application warnings are **not** asserted to be a
verified durable audit chain. Audit-write failure remains BLOCKED and reports
`preparation_audit=FAILED`; it is not silently treated as recorded.

## Regression and independent export

No AF_PACKET socket, privileged launcher, traffic generator, or actual model
inference was used. The existing socket-denying regression guard stayed enabled.
Model environment faults/readiness are mocked in the new Backend tests; actual
WSLg tests use isolated data directories and deny authentication launch.

* Initial focused tests: **33 passed in 4.40s**.
* Broad related regression: **304 passed, 3 deselected in 80.93s**. This was before
  the final inactive-counter/origin reset and colon-code compatibility refinement.
* Focused final reset/GUI/diagnostic/evidence tests: **33 passed in 3.05s**.
* Final GUI error-shape cases: **16 passed in 0.13s**.
* Final-source independent Export: **305 passed, 3 deselected in 66.40s**.
* Ruff `check src tests`, whole-workspace format (**1,050 files**), and
  `git diff --check`: PASS.

Counts are separate executions with overlap, not a sum. The three deselected
cases are actual RF/LR model comparisons; no new actual inference result is
claimed for the preparation/UI changes. Export used Git HEAD plus only ten owned
files, with original user/Replay changes excluded, clean ML HEAD source, and
trusted read-only external Artifact references. Final file SHA256 values were
compared between Workspace, Export, Stage, and commit. Delivery identity is the
commit containing this report; no self-referential commit hash is embedded.

Coverage includes eight-session refusal, resource/Bundle failure, real ordinary
Unix file-lock contention, storage/audit failure, unknown exceptions, string/type
bounds, READY, stale READY callback/poll, no unauthorized authentication, normal
Stop/Restart with a new identity, and GUI Stop/Restart that correctly keeps an
archive-full root blocked. The actual WSLg failure screen shows the Backend code,
NOT_PREPARED, copy disabled, zero inference, and operational Gate BLOCKED.

The existing capacity-calibration evidence remains immutable. Two exact source
snapshots from `89a7989` are stored as **non-executable `.txt` test data**, and the
historical evidence test binds those paths to their original SHA256. The live
preparation/UI code has separate current regressions. Historical model/soak
results were not rerun or relabeled as this task's validation.

## Preserved security boundaries and next Native validation

Helper SHA256 remains:
`375c06dbeb4e14c881fa496459182677b4efaa293845ecfac0dab0da663c4703`

Bundle Digest remains:
`56ec48caac56a248fc0eeb5bb09c4fae4176482ed19ea8c48526f7638ae8bb31`

Calibrated manifest file SHA256 (also matched to the baseline Git blob):
`ade48c4ebc3d06a56e29bb735513540030c5e3b3ec472ec874523c7a120797c6`

No Helper, Manifest, policy, Artifact, Raw data, existing session/SQLite/audit, or
checkpoint was changed. The eight-session ceiling, resource gate, capability
drop, counter/drop checks, RESEARCH_ONLY, DNS9 parity gate, operational BLOCKED,
and WRITE_DENIED remain in force. No sudo, setpriv, pkexec, or capture was run.

This change exposes the blocker; it **does not archive or delete evidence** or
raise the ceiling. The operator must first preserve/archive old sessions under
their own retention decision, or explicitly select a fresh isolated validation
data directory using the existing `--data-directory` CLI option. A new root is
not selected automatically. Existing sessions/commands cannot be reused as a
new session. Then recheck environment, policy, SHA/Bundle, and explicit user
approval before any user-executed Native run. **Native E2E remains pending**.
