# Linux SOC v1 — Visual redesign and demo UX

## Scope

Baseline: `9ea85bc86ba98aa6649cf3f796784e35ed14f4b9`, `main`.
Actual environment: WSL2 Ubuntu / WSLg, Python 3.12.14, Tk 9.0.4.
This changes Tk presentation, read projections and GUI tests. Existing Collector,
Detection, Investigation, models, Policy, Approval, Operator socket, Restricted
Executor, simulation and Self-Improvement engines are reused. No new backend,
HTTP API, model, feature producer, automatic promotion or real OS response.

## Before audit

All eight existing actual screenshots in `gui-screenshots/` were reviewed before
editing. They remain unchanged; the new captures use a separate directory.

| Before image | Main findings |
|---|---|
| `dashboard-live-wsl.png` | Runtime/health too small; equal-sized metadata cards hide priorities; graphs only 170px high |
| `queue-trend-fixture.png` | Changing values are genuine but small; no interactive sample inspection |
| `investigation-fixture.png` | Hashes dominate; sparse table consumes most space; assessment/source separation difficult to scan |
| `investigations-live-wsl.png` | One row in a large empty table; little incident context without JSON |
| `models-native-fixture.png` | Verified fixture and blocked operational paths only visible as table codes |
| `approval-fixture.png` | Exact actions and expiry buried in JSON; Approve/Reject look identical |
| `self-improvement-fixture.png` | Evaluation results and metrics buried in JSON; no distribution/comparison overview |
| `scenario-fixture.png` | Real stage outcomes exist but require JSON reading; no clear activity indicator |

The installed uv Tk reports only the X11 `fixed` family, regardless of requested
font. A requested 32px DejaVu font was actually 13px. Changing style sizes alone
would not solve this. No existing screenshot was retouched or replaced.

## Design system and typography

| Role | Value |
|---|---|
| Background / sidebar | `#0B1220` / `#111C2E` |
| Surface / elevated surface | `#17243A` / `#20314A` |
| Primary | `#38BDF8` |
| Primary / secondary text | `#F1F5F9` / `#94A3B8` |
| Healthy / warning / critical / unknown | `#22C55E` / `#F59E0B` / `#EF4444` / `#64748B` |
| Page / section / KPI text | 28px / 18–22px / 30px |
| Body / metadata | 13px / 11–12px |

UNKNOWN KPI text uses 17px so the whole state fits instead of displaying `UN...`.
Neutral surfaces carry the layout; colors carry status. UNVERIFIED/UNAVAILABLE
cannot inherit the positive color of VERIFIED. NOT_READY and INCONCLUSIVE are
warnings. Regression is critical; `NO_FP_FN_COUNT_REGRESSION` is a warning rather
than a success/operational readiness claim. A stopped/unknown Runtime cannot get
a green active Hero even if an inconsistent input DTO contains READY/HEALTHY.

The GUI retains Tk. `typography.py` uses **already installed** system Pango/Cairo
through a narrow standard-library ctypes bridge to render scalable Unicode into
Tk PhotoImages. There is no GTK window, framework installation, font download or
system font configuration change. DejaVu Sans and installed Nanum fallback render
English, Korean and numbers with zero missing glyphs in the tested phrase.
The main screen/footer includes Korean, not only a detached font test.

This follows the system APIs for [Pango layout rendering](https://docs.gtk.org/PangoCairo/func.create_layout.html),
[absolute pixel sizing](https://docs.gtk.org/Pango/method.FontDescription.set_absolute_size.html)
and [Cairo PNG streams](https://www.cairographics.org/manual/cairo-PNG-Support.html).
Only plain text is rendered, never Pango markup supplied by an LLM.
Rendering/cache access is restricted to the Tk creator thread; image cache size
is bounded to 192. Missing system libraries cause an explicit launch failure.

`components.py` contains small Tk labels/buttons, a status Hero and a keyboard
selectable Canvas list. The Canvas list replaces only Treeview rendering because
the bundled Tk cannot render scalable system fonts in its cells. Domain records,
selection IDs, commands and validation are unchanged. Visible rows are rendered
on demand; a 1,000-row test does not allocate 1,000 rows of font images. No general
UI/platform framework was introduced.

## Dashboard and data contracts

The Dashboard order is Hero → six KPI cards → large activity charts → timestamped
recent findings and investigation distribution → collapsed technical detail.
The Hero exposes runtime, health, readiness, collector, Queue, last GUI measurement
time, input label and assessment mode. Failed status polling resets the header
and Hero to UNKNOWN / NOT_READY rather than leaving an earlier READY displayed.
Returning to a cached page does not invent a newer measurement timestamp.

| Visual | Existing data and unit |
|---|---|
| Retained events | Sum of actual persistent Queue states; retained journal records, **not cumulative lifetime collection or accepted auth count** |
| Active findings | PENDING + RUNNING investigation jobs; not confirmed attacks |
| Completed | DONE_READ_ONLY + DONE + DONE_SCRIPTED |
| Pending approval | Existing simulation/restricted approval views; unknown if bounded view completeness cannot be established |
| Queue backlog | Existing PENDING + CLAIMED Queue count |
| Failed jobs | Existing FAILED investigation jobs |
| Recent activity | Up to four validated findings with actual source `last_seen` UTC; not LLM-generated timestamps |
| Investigation distribution | Existing RuntimeStore job states |

`queries.py` performs read transactions, existing digest/finding/provenance
validation and aggregate/read projections. No SQL mutation is added. Accepted
authentication count is retained in the detailed snapshot; it is not confused
with all journal Queue records. Metric failures stay UNKNOWN, never fabricated 0.

`--source-label UNVERIFIED|LIVE_WSL|FIXTURE` is an explicit **presentation label**,
not an attestation, capability, model-inference permission or source rewrite.
Default is UNVERIFIED. It is visible on every screen. Native-parser fixtures can
retain `NATIVE_OS` in the original backend contract; the fixture test's global
INPUT label remains FIXTURE. Original stored provenance is not silently relabeled.
Assessment mode SCRIPTED/READ_ONLY/REAL_LLM is separate from the input label.

## Interactive charts

- Existing bounded MetricHistory is reused: 120 samples by default, max 1,000.
- Queue and completed plots are 244px high, measured counts with an elapsed-time
  x-axis. The axis is GUI monotonic measurement time, not source event time or
  a production latency benchmark.
- Hover shows a measured sample/crosshair; Left/Right keys inspect samples after
  focusing a chart. Missing samples remain UNKNOWN gaps.
- An identical measurement at the same timestamp is idempotent; conflicting
  values at the same timestamp fail. A later poll with unchanged counts is a
  legitimate flat sample, not another completed investigation.
- Runtime/store changes clear history. Out-of-order time is rejected. No random
  data, interpolation to fill gaps or animation implying nonexistent events.
- Approval/feedback distributions use actual queried records. A single category
  is drawn as a full ring; empty data is NO_DATA and unavailable data is UNKNOWN.
- Successful approval/action updates trigger a fresh **read-only** ledger query
  before displaying its new distribution; the one selected action is not
  misrepresented as the entire ledger.
- Baseline/Candidate F1 uses stored, finite metrics with a nonempty matching
  Ground Truth digest. Missing denominators/metrics remain UNKNOWN. The stored
  regression verdict and Promotion BLOCKED remain visible. These are offline
  fixture results, not model accuracy or operating improvement evidence.

Polling remains 15 seconds, off the UI thread. Repeated poll scheduling leaves
only one pending poll timer and one in-flight backend action. Model inventory does
not infer on polling. Native model probes still require an explicit confirmed
action through the existing service.

## Six screens and governed actions

| Screen | UX changes and unchanged boundary |
|---|---|
| Dashboard | Status Hero, six measured KPIs, larger interactive trends, recent source times, state distribution |
| Investigations | Incident/rule/severity/status header; actual event timeline and tool step progress; source references separated from advisory assessment; digest copy |
| Security AI Models | Four model/source cards; native fixture history and operational NOT_INFERABLE shown simultaneously; existing status API and explicit probe |
| Response & Approval | Action/target/expiry/evidence summary; distinct approval/rejection controls; ledger distribution; original authenticated socket and digest binding |
| Self-Improvement | Loaded record count, authenticated opinion distribution, stored Baseline/Candidate comparison, regression and human review; no activation control |
| Scenario Demo | Existing S01–S12 list, explicit FIXTURE/SCRIPTED labels, indeterminate activity and actual reported stage outcomes/audit |

Raw JSON is collapsed by default, selectable, scrollable and redacted through the
existing display filter. IDs/digests can be copied without making them primary
content. Scalable lists support keyboard focus, arrows, Home/End, mouse wheel,
scrollbars and bounded rendering. Page content scrolls vertically at small sizes.

Approval availability is only a UX aid. The original Policy/Approval/Executor
revalidates every request at execution time. Actor strings are not credentials;
OS peer UID/allowlist, current record digest and exact action binding remain
authoritative. Changing the response ledger clears selection. Rollback is enabled
only for a changed restricted test resource with its original stored receipt;
rollback still needs a separate authenticated approval.

Restricted Marker writes remain real changes to the registered temporary test
resource, labeled TEST_RESOURCE_CHANGED / ROLLED_BACK. Simulation is labeled
SIMULATED and changes no resource. No firewall/account/process response is added.
Network/DNS operational inputs remain NOT_INFERABLE; Synthetic v2 and Operational
Provenance v3 are unchanged. LLM text never becomes observed evidence or authority.

## Actual demo journey and visual QA

Actual mapped WSLg windows are exercised at **1920×1080 and 1366×768**. Screenshots
use the existing XGetImage capture helper. They are actual windows, not mockups or
image generation. Existing Before images remain in `gui-screenshots/`; new After
images are listed below.

| Journey | Data / execution | Result |
|---|---|---|
| Module launch, duplicate refusal, normal close/SIGTERM | Actual WSLg process and existing ownership lock | PASS |
| Dashboard and graphs | Existing persistent Fixture Queue operations | 4→0 repeated three times; completed 1→2; matched store values |
| Scenario S03 | Existing isolated runner | Actual reported detection/investigation/audit; no guessed live stage progress |
| S01–S12 | Existing runner | PASS, all twelve |
| Investigation | Validated fixture and actual WSL records | Evidence references, source times, tool status, assessment mode, copy/fold tested |
| Native model cards/probe | Real existing Quality/Edge/DNS backends on explicit synthetic precomputed Features | Advisory fixture execution; no production feature inference |
| Pending approval / approve / reject / simulation | Fixture finding, real OS-peer Operator socket | Actual UI buttons exercised |
| Restricted test action / rollback | Registered temporary Marker | Actual state change, separate rollback approval, restored state |
| Self-Improvement | Authenticated Fixture feedback and stored offline evaluation/review | INCONCLUSIVE / Promotion BLOCKED; no automatic change |
| Actual WSL collection/restart | Read-only retained journald events | PASS, 1 accepted authentication / 1 completed READ_ONLY finding; RESUMED_EXACT after restart |
| Audit/recovery | Existing stores, replay and lifecycle tests | Source/receipt/audit guards reused |

Scenario S03's isolated runner and an attached Continuous Runtime are **separate
workspaces**. The GUI shows the Scenario's actual reported detection/investigation
stages, then the demo reviews an explicitly attached Fixture Runtime's findings
and approvals. It does not claim those are the same Incident or silently import
a Scenario into an operational Runtime. The runner provides final stage results,
not live per-stage notifications, so running activity is indeterminate rather
than a fabricated percentage or fabricated Current Stage.

UI automation confirms dialogs using a test harness; the kernel UID authentication
is real but this is not evidence of independent human intent. Product dialogs
still require operator interaction. Fixture and actual WSL evidence stay separate.
No real LLM API is required or invoked in this redesign validation.

Visual QA found and corrected: tiny fixed fonts, UNKNOWN KPI truncation, clipped
Panedwindow details/buttons at 1366×768, a single-category ring drawing as an empty
arc, stale approval distributions after actions, an incorrect assessment nesting
path (`AssessmentResult.threat_assessment`), and regression-code color ambiguity.
An additional reproducible wheel test showed both a nested table and the outer
page scrolling together. Returning `break` after the table consumes the wheel
event fixes this; the test asserts table movement and unchanged outer position.
The source and audit validators were not relaxed to fix display problems.

## Reproduction and test results

```bash
.venv/bin/python -m soc_agent.gui
.venv/bin/python -m soc_agent.gui --runtime /private/runtime --source-label LIVE_WSL

RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/unit/gui tests/integration/gui tests/gui_wslg_checks.py tests/gui_visual_checks.py

# Explicit native/actual WSL checks, using an already verified environment.
RUN_LIVE_LLM_TESTS=0 \
SOC_EXTERNAL_ARTIFACT_ROOT=/private/artifacts \
SOC_EXTERNAL_INFERENCE_PYTHON=/private/native/bin/python \
SOC_GUI_SCREENSHOTS=/private/screenshots \
.venv/bin/python -m pytest --import-mode=importlib -q tests/gui_environment_checks.py

RUN_LIVE_LLM_TESTS=0 .venv/bin/python -m pytest --import-mode=importlib -q \
  tests/integration/scenario tests/integration/linux_runtime \
  tests/integration/live_operator tests/integration/response_simulation \
  tests/integration/restricted_response tests/integration/feedback_loop \
  tests/integration/package_status tests/unit/package_status \
  tests/unit/approval tests/unit/execution tests/integration/external_read_only_backend

.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check .
git diff --check
```

Paths in examples are placeholders. The previous verified isolated native
environment was reused read-only. No Python environment was reconstructed.

| Execution | Result | Scope |
|---|---|---|
| Independent baseline Git Export + UI change: all GUI, WSLg, native and actual WSL checks | **43 passed, 0 failed**, 173.92s | Includes native three-model inference, actual WSL collection/restart and both capture sizes |
| Final Export GUI regression after the wheel propagation fix | **40 passed, 0 failed**, 59.17s | Final production Python snapshot; unit, backend, WSLg, full UI journey, scrolling/focus/hover |
| Extra actual Queue capture at both sizes | **1 passed**, 6.96s | Test-only extra capture step; no production change after the 40-test run |
| Existing Scenario / Runtime / Operator / Restricted Response / Feedback / model status / governance security regressions | **390 passed, 0 failed**, 468.31s | Existing workspace, underlying engines unchanged |
| Ruff source/tests | PASS | Whole current source/test tree |
| Ruff format check | PASS, 847 files | Whole current tree |
| Git diff check | PASS | Final changes and preserved user work |

Counts are execution-specific and overlap; they are not summed. Earlier failed
visual checks and intermediate runs are not final PASS evidence. Local output
files are `/tmp/soc-ux-export-tests.log`, `/tmp/soc-ux-final-focused.log`,
`/tmp/soc-ux-queue-capture.log`, `/tmp/soc-ux-regression.log`,
`/tmp/soc-ux-final-lint.log` and `/tmp/soc-ux-final-format.log`.

The independent `git archive` uses committed baseline source plus only this UI
change, excluding dirty Reliability Replay, README, pyproject and other user work.
All 16 GUI-related Python files in the test overlay have recorded SHA-256 values;
they are checked against final source and staged content before committing.
This is source reproducibility with existing dependencies, not a clean install.

The actual WSL run observed existing journald for 35 seconds, restarted and
observed for 5 more seconds; the helper's elapsed value including UI capture and
lifecycle overhead was 46.91s. One supported retained authentication event, one
READ_ONLY investigation and Queue backlog 0 were recorded; cursor resumed exactly.
The Dashboard's 192 retained Queue records in its screenshot are **not 192 accepted
authentication events**. No login attempts, LLM provider requests or OS security
configuration changes were generated. The separate native probe returned three
results in two correlation groups using explicit synthetic precomputed features.

## Before / After image index

Before examples: [Dashboard](gui-screenshots/dashboard-live-wsl.png),
[Investigation](gui-screenshots/investigation-fixture.png),
[Models](gui-screenshots/models-native-fixture.png),
[Response](gui-screenshots/approval-fixture.png),
[Self-Improvement](gui-screenshots/self-improvement-fixture.png),
[Scenario](gui-screenshots/scenario-fixture.png).

| Final report image | 1920×1080 | 1366×768 |
|---|---|---|
| Dashboard, actual WSL | [image](gui-ux-screenshots/dashboard-live-wsl-1920.png) | [image](gui-ux-screenshots/dashboard-live-wsl-1366.png) |
| Dashboard, Fixture | [image](gui-ux-screenshots/dashboard-fixture-1920.png) | [image](gui-ux-screenshots/dashboard-fixture-1366.png) |
| Actual Fixture Queue mutation | [image](gui-ux-screenshots/queue-store-fixture-1920.png) | [image](gui-ux-screenshots/queue-store-fixture-1366.png) |
| Investigation, Fixture | [image](gui-ux-screenshots/investigation-fixture-1920.png) | [image](gui-ux-screenshots/investigation-fixture-1366.png) |
| Actual native models, synthetic Features | [image](gui-ux-screenshots/models-native-fixture-1920.png) | [image](gui-ux-screenshots/models-native-fixture-1366.png) |
| Approved test Marker changed | [image](gui-ux-screenshots/restricted-marker-fixture-1920.png) | [image](gui-ux-screenshots/restricted-marker-fixture-1366.png) |
| Separately approved rollback | [image](gui-ux-screenshots/approval-rollback-fixture-1920.png) | [image](gui-ux-screenshots/approval-rollback-fixture-1366.png) |
| Self-Improvement, Fixture | [image](gui-ux-screenshots/self-improvement-fixture-1920.png) | [image](gui-ux-screenshots/self-improvement-fixture-1366.png) |
| Scenario S03, Fixture | [image](gui-ux-screenshots/scenario-s03-fixture-1920.png) | [image](gui-ux-screenshots/scenario-s03-fixture-1366.png) |
| Timeout / unknown state | [image](gui-ux-screenshots/error-unknown-1920.png) | [image](gui-ux-screenshots/error-unknown-1366.png) |

There are 20 new actual captures; original Before files remain untouched. Screens
with synthetic chart boundary snapshots are not used as pipeline evidence. Live
images mean retained WSL records, not newly generated attacks.

## Change inventory

- Modified: GUI `__main__.py`, `app.py`, `backend.py`, `charts.py`, `queries.py`.
- New: GUI `components.py`, `typography.py`, `presentation.py`.
- Modified explicit checks: `tests/gui_wslg_checks.py`, `tests/gui_environment_checks.py`.
- New checks: `tests/gui_visual_checks.py`, `tests/unit/gui/test_visual_contracts.py`.
- New: this report and 20 actual screenshots.
- Existing user changes and untracked Reliability Replay remain outside this commit.

## Remaining limitations

- Standard Tk platform dialogs and raw code details retain the bundled Tk font;
  primary navigation, titles, KPIs, lists, charts and summaries use scalable text.
- Long metadata is ellipsized for layout; complete values remain in copyable
  technical details. Smaller windows may need vertical scrolling.
- Current plots are session history and stored snapshots, not a persistent
  observability service or a long-duration memory/performance certification.
- Native input producer parity remains missing; no Network/DNS operating inference
  or score/accuracy chart is introduced.
- A real LLM GUI run, physical Linux, Windows, AWS, packaging/deployment and actual
  OS security response are outside this validation. Future work should prioritize
  physical Linux usability/permissions and longer desktop stability observation.

Verdict: **VERIFIED for this WSL2 Ubuntu/WSLg UI redesign and existing backend demo
scope**. It does not certify deployment, operating model producer parity, real
LLM operation in this run, or actual OS security response.
