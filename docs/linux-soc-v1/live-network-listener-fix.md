# Live Network Unix listener lifecycle fix

Validation date: 2026-10-16 (WSL2 Ubuntu / WSLg).
SOC HEAD: `df96d37d951e0fdf3ba047768aa024dbf353052a`.
ML HEAD: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde` (unchanged).

Result: **PARTIAL**. The listener lifecycle fix is verified with ordinary-user
Unix sockets and actual WSLg GUI tests. Actual privileged Live E2E remains
**IMPLEMENTED_BUT_NOT_LIVE_VERIFIED**. Selective commit/push is **BLOCKED** by the
uncommitted Live Network prerequisite described below.

## 1. Root cause

`Session.socket_address` is the abstract Linux AF_UNIX address
`\0soc-live-<session UUID>` (`@soc-live-<UUID>` in `ss`/`/proc/net/unix`).
It is SOCK_SEQPACKET, not a filesystem socket. No socket file is expected in the
session directory. A retained `session.json` or SQLite database does not establish
that a listener is accepting connections.

Previously, `HelperCapture.__init__` bound/listened synchronously, but
`handshake()` stopped accepting after an undocumented-in-GUI 120-second
operator-authentication deadline. `LiveMonitoring._run()` then closed the
listener. The GUI retained the helper command, and its copy button did not check
listener liveness. A later helper execution therefore reached a dead abstract
address and raised `ConnectionRefusedError` (errno 111).

This defect was reproduced against the original source by advancing only the
transport module's test monotonic clock beyond 120 seconds:

```text
SO_ACCEPTCONN before wait: 1
handshake: HELPER_AUTHENTICATION_WAIT_EXPIRED
connect after controller cleanup: ConnectionRefusedError 111
```

The backend already strongly owned the capture object and `_run` task. The GUI
backend event loop runs in its own persistent thread; it was not a per-button
`asyncio.run()` loop. The confirmed defect is the hidden accept deadline and
stale GUI command, rather than missing bind/listen or proven garbage collection.
The former thread-backed handshake also lacked an explicitly joined task on
parent cancellation.

The historical failed helper's precise wait duration is unavailable, so the
120-second expiration cannot be attributed to that particular attempt with a
timestamp correlation. The original GUI PID 90946 was absent during this audit.
The retained default GUI session still contained its session file and Runtime DB,
with neither `verified-ready.json` nor `verified-closed.json`. Those files were
preserved; no connection was made to a user session during this work.

## 2. Changed files

Only these seven files were changed/added for this fix, relative to the worktree
at the start of this task:

- `src/soc_agent/security_ai/operational/network_capture/helper_transport.py`
- `src/soc_agent/security_ai/research/live_service.py`
- `src/soc_agent/gui/backend.py`
- `src/soc_agent/gui/live_view.py`
- `tests/unit/live_network/test_listener.py` (new)
- `tests/gui_live_network_checks.py`
- `docs/linux-soc-v1/live-network-listener-fix.md` (this report)

The approved helper, `live_session.py`, capture/parser/permission code, Producer,
models, and pre-existing demo evidence were not modified.

## 3. Listener lifecycle

1. Prepare verifies the existing research environment and creates a new private
   session, then synchronously binds/listens. Bind failure returns ERROR without
   a command and closes the failed socket.
2. `listener_ready()` checks actual `SO_ACCEPTCONN`, closed state, and whether a
   connection has already been accepted. The controller also requires an owned,
   unfinished session task before issuing a command.
3. The observer waits until explicit Stop, GUI close, transport failure, or the
   first helper connection. Authentication waiting has no hidden 120-second
   expiry. This does not extend capture: the helper still enforces 60 seconds /
   512 frames maximum on `lo`.
4. After one accept, the listening socket closes. The existing bounded two-second
   READY read and process/capability/raw-socket attestation remain enforced.
   Listener READY is not verified capture READY and does not imply LIVE.
5. The controller explicitly owns the thread-backed handshake task. Cancellation
   closes the listener/channel, interrupts a connected READY read, and joins the
   handshake before Stop/GUI shutdown completes. No automatic reconnect/retry.
6. Stop is idempotent; old addresses reject connections. Re-Prepare creates a
   different session UUID/address. Retained files survive, but reopening the GUI
   does not recreate a listener or expose a retained helper command.

## 4. GUI state synchronization

- Prepare exposes a helper command only with `listener_ready: true`.
- The screen distinguishes `LISTENER READY (no capture yet)` from verified live
  collection. STARTING/HELPER_VALIDATING and an owned active task prevent another
  Prepare.
- Copy asks the backend again for a command bound to the current session ID;
  stopped/failed/foreign session requests return BLOCKED without a command.
- Polling clears displayed commands and disables Copy when readiness disappears.
  Listener/handshake failure is shown in Last Error with instructions to Stop and
  prepare a new session. No readiness is inferred from a directory or DB.
- Navigation preserves the backend-owned listener. GUI close stops and joins it.
  Commands already copied into a terminal cannot be recalled; their old abstract
  address remains closed after Stop/restart.

## 5. Security boundaries and helper SHA

Approved helper SHA256, unchanged:

```text
9699cd29f14851287d03e8883ddc765c95a89e9e8169281b4be0b949bff4d87d
```

No `sudo`, `pkexec`, privileged `setpriv`, AF_PACKET capture, test network traffic,
model modification, or OS security WRITE was performed. No credential was
collected. Tests used temporary private session directories and AF_UNIX only.
Raw payload retention remains disabled. The helper's temporary CAP_NET_RAW and
post-open capability drop checks were not changed or newly exercised.

`RESEARCH_ONLY`, `NOT_INFERABLE`, `OPERATIONAL_INFERENCE_BLOCKED`, and
`WRITE_DENIED` remain enforced. The normal user's test client cannot establish
real capture readiness. One positive framing/handshake test replaces only raw
socket/capability attestation with a documented same-UID/GID Unix peer assertion;
negative-client tests retain fail-closed parsing. These are transport tests, not
privileged-helper/capability-drop evidence.

## 6. Regression results

Each row is a separate invocation, not an aggregate pass count. Final results:

| Invocation | Result | Scope |
| --- | --- | --- |
| `tests/unit/live_network tests/integration/live_network` | 43 passed | Includes 7 new listener tests and existing actual research-artifact fixture inference / audit recovery tests |
| `tests/gui_live_network_checks.py` | 1 passed | Actual WSLg: Prepare, fresh command copy, duplicate click, Stop, new identity, navigation, unexpected close, invalid ordinary Unix client, active-listener GUI close; 1920×1080 and 1366×768 |
| GUI / Research Adapter / DNS Research / Final Demo evidence regressions | 173 passed | `tests/unit/gui tests/integration/gui tests/unit/research_adapter tests/integration/research_adapter tests/unit/dns_research tests/integration/dns_research tests/unit/final_demo` |
| Prerequisite-inclusive export: Live Network | 43 passed | HEAD + existing Live feature allowlist + this fix; no Reliability Replay |
| Prerequisite-inclusive export: actual WSLg check | 1 passed | Same explicit trusted artifact environment, no privileged helper |
| Ruff `check src tests` | PASS | Whole source/test scope |
| Ruff `format --check .` | PASS | Whole repository; existing ML files untouched |
| `git diff --check` | PASS | Worktree |

All guarded regression invocations reported **0 attempted AF_PACKET/IPv4/IPv6
socket creations**. Actual model calls in existing integration tests use
explicit FIXTURE metadata; they are not Live capture evidence. The original
36-test pre-change-suite run also passed before adding the 7 new tests; it is
not counted again as new coverage.

Regression commands used the existing no-capture audit wrapper:

```bash
.venv/bin/python -m tests.native_capture_verification_guard \
  --import-mode=importlib -q \
  tests/unit/live_network tests/integration/live_network
.venv/bin/python -m tests.native_capture_verification_guard \
  --import-mode=importlib -q tests/gui_live_network_checks.py
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

The wrapper invokes pytest and denies new AF_PACKET/AF_INET/AF_INET6 sockets.
New tests cover kernel listener readiness, a real same-user Unix connection,
framing/handshake, a clock jump beyond the former deadline, task ownership,
unexpected listener close, invalid READY, Stop while waiting for READY, duplicate
bind/Prepare, old-session rejection, restart, and preserved private permissions.

## 7. Independent export and commit blocker

Current HEAD does not contain the preceding Live Network implementation. Its
26-file allowlist remains uncommitted, including `live_helper.py`,
`live_session.py`, `live_input.py`, the controller/view, and required model/worker
extensions. The index was empty on entry and remains unchanged.

The required strict export, **HEAD + only this task's changed files**, failed
collection with:

```text
ModuleNotFoundError:
No module named 'soc_agent.security_ai.operational.network_capture.live_helper'
```

A separate dependency-inclusive export using the prior 26-file allowlist plus
this fix (27 distinct overlay files, including the new test, before this report)
passed 43 Live tests and the actual WSLg test. Its package source and tests were
exported; trusted local research artifacts/interpreter were read by explicit
reference, not copied or modified. This demonstrates isolation from Reliability
Replay but does not make a listener-only commit independently reproducible.

Accordingly **no Stage, Commit, or Push was performed**. Adding all prerequisites
would exceed this task's listener-only staging scope. The next Git decision is to
review/commit the existing Live Network prerequisite separately (or explicitly
authorize a combined scope), then export and selectively commit the fix. No
force operation, stash, cleanup, user-stage modification, or raw/model/DB staging
was used. Original changes and protected evidence hashes were checked separately.

## 8. Remaining Live E2E blocker and manual retry

Actual privileged helper/capture E2E still requires a new user-executed session.
Do not reuse the command from the failed session.

1. Close any old GUI normally, then launch the updated worktree:

   ```bash
   cd ~/kdt-linux/autonomous-soc-agent
   .venv/bin/python -m soc_agent.gui
   ```

2. Open Live Network; select Quality/Edge; click **Prepare live session** once.
   Confirm **LISTENER READY (no capture yet)**. The GUI must remain open.
3. Optionally inspect the ordinary-user listener in another terminal:

   ```bash
   ss -xlpn | rg '@soc-live-'
   ```

   Its UUID must match the newly prepared session. No socket file is expected.
4. Click **Copy helper command**. Review the unchanged helper SHA above, `lo`,
   60-second / 512-frame bounds, UID/GID, and temporary CAP_NET_RAW scope. Only
   the user authenticates/runs that freshly generated command in their terminal.
   The GUI does not request a password or execute it. A command copied earlier
   is unusable after Stop, failure, GUI close, or a new session.
5. Stop via **Stop live** or Ctrl+C in the helper terminal. Preserve the new
   session's receipts/DB for subsequent read-only E2E verification. If permission
   setup fails, do not bypass it; report BLOCKED. No successful Live capture,
   capability drop, or Live model inference is claimed by this listener fix.
