# Final GUI visual redesign and UX validation

Validation date: 2026-10-16. Scope: presentation of existing Backend contracts.
SOC baseline: `261502209a0dd1735d176b555d8b99bccfcd9723`.
ML baseline: `e1a01260f0463a38d4d778859bc2a86f8e9cfbde`.
Tkinter, ApplicationService, research service, isolated workers, source stores,
investigation and governance remain the existing implementations. No ML changes.

## 1. Design system

Dark navy `#0B1220`, sidebar `#111C2E`, slate surfaces `#17243A` / `#20314A`,
off-white `#F1F5F9`, muted `#94A3B8`, cyan `#38BDF8`, violet `#A78BFA`,
emerald `#34D399`, amber `#FBBF24`, coral `#FB7185` and unknown slate `#64748B`.
Color accompanies explicit state text; model accents identify domains, not risk.
Model cards use a 10 px corner radius and a thin domain accent. Chart surfaces
remain rectangular for readable axes. Existing Pango/Cairo text rendering is
reused with large KPI values, section headings, body text and muted metadata.
No new dependencies or GUI framework.

Buttons retain keyboard focus, hover/selected states and a readable disabled
state. Read-only model selectors now have a dark, high-contrast surface.
Long SHA values are shortened in summaries; original values remain copyable in
technical details. Display masking supplements existing credential redaction:
home-directory prefixes and user/host/operator identity fields are masked without
modifying Backend records or evidence.

## 2. Before / after

The retained [before dashboard](stabilization-screenshots/unified-dashboard-1366.png)
had long status strings in small cards above the graphs. Important research
charts were pushed below the first viewport. The research control row exposed
internal profile codes and required a prepare step before replay. Detail views
made raw technical records compete with investigation and audit results.

The [1920 after dashboard](final-gui-screenshots/dashboard-1920.png) and
[1366 after dashboard](final-gui-screenshots/dashboard-1366.png) put current state
and two large, explicitly sourced charts first. All screenshots are captures of
mapped Tk windows on actual WSLg; none are generated mockups.

## 3. Dashboard layout and status accuracy

The existing system-health hero remains first, followed by eight compact states:
Runtime, Authentication collector, Network, DNS collector, Research AI,
Operational AI, queue backlog and current investigations. Eight columns become
four columns / two rows when the content area is narrower than 1450 px.
Research observatory graphs precede the four large model cards. Invocation and
latency charts, advisory summaries and existing Runtime charts follow below.
The content area scrolls; status and primary chart remain accessible at 1366 and
1280 widths.

All labels project existing DTOs through `gui.insights`. Retained Authentication
events do not make a stopped Runtime LIVE. Authentication readiness requires
current Runtime/collector/health/readiness support. A packet collector is LIVE
only when the Backend reports RUNNING, Runtime RUNNING and NATIVE_AF_PACKET.
DNS explicitly shares the existing packet collector state; it does not imply
DNS query visibility. Collector errors remain ERROR. Research readiness is
RESEARCH, separate from BLOCKED / NOT_INFERABLE operational inference.
Missing/failed/invalid measurements remain UNKNOWN rather than zero.

The actual screenshot Runtime is STOPPED / NOT_READY with retained NATIVE_OS
Authentication data. Research environments are ready for explicit replay;
workers are stopped after inference. No fresh live collection was performed.

## 4. Model status

Network Quality, Network Edge, DNS Security and Authentication cards show
readiness, required input origin, validation level, artifact integrity, worker
state, stored call/event count, last result date and error/gate information.
Unknown storage does not appear as a successful zero-count session.
RUNNING requires an actual current worker for that model. Stored results are
labelled **stored calls** or **retained events**, with UTC dates. A restored
receipt does not count as a new invocation.

Network remains `READY_FOR_OFFLINE_REPLAY`, OFFLINE_PCAP, research-only.
DNS remains DNS9 FIXTURE only, Producer parity unverified. Authentication
retains its separate Linux operational provenance and stopped collector state.
Operational model readiness is never inferred from research readiness.

## 5. Charts and data integrity

| Chart | Actual source and meaning | Missing data |
|---|---|---|
| Offline flow trend | Unique replayed OFFLINE_PCAP flow packet counts; Quality/Edge sharing a flow is deduplicated | NO_DATA / UNKNOWN |
| DNS score | Stored DNS9 fixture receipts, UTC/replay order, uncalibrated scores | NO_DATA / UNKNOWN |
| Invocation timeline | Up to ten existing research receipts at their actual UTC timestamps, separated by model | NO_DATA / UNKNOWN |
| Model latency | Latest observed per-model receipt latency; Network prediction and DNS package timings differ, so this is explicitly not a benchmark | NO_DATA / UNKNOWN |
| Advisory distributions | Actual recorded model invocations and separate per-model threshold bins | NO_DATA / UNKNOWN |
| Investigation distribution | Existing research investigation statuses, separate from operational incidents | NO_DATA / UNKNOWN |
| Runtime queue/completion | Existing bounded MetricHistory and Backend snapshots | UNKNOWN on failed/absent reads |

Existing Runtime chart history, duplicate-snapshot suppression and runtime-ID
reset contracts are reused. Counts are not generated by timers. DNS scores are
not attack probabilities. No combined Network/DNS risk score is created.
The latest Network summary exposes measured packet/drop/gap fields only when
available. No severity or recovery-rate chart is manufactured from missing DTO
fields. There is no fake live-traffic series while collection is stopped.

The final actual demo plotted packets **2 → 6** for two unique offline flows and
DNS scores **0.55859375 → 0.0**, preserving measured zero. Six native receipts
produced six invocation points and three latest latency bars. Existing chart
tests also cover queue 4→0→4→0, completion count increments,
monotonic history, unknown data, resize and bounded storage. Snapshot/Runtime
scope isolation remains the existing contract.

## 6. Demo UX

Launch remains:

```bash
cd ~/kdt-linux/autonomous-soc-agent
.venv/bin/python -m soc_agent.gui
```

Open **Research Demo**, select Network Quality + Edge / individual model / DNS,
choose an existing verified input and press **Run Demo**. The explicit click
composes the existing prepare and replay operations when stopped. No model runs
at GUI launch or during status polling. The input badge explains OFFLINE_PCAP
versus precomputed DNS9 FIXTURE before execution.

Controls disable while busy, and duplicate replay dispatch is rejected.
The existing background worker keeps Tk responsive. The UI reports preparing,
worker running, completion, retained/cached result, unknown failure without
automatic retry, and the existing Stop lifecycle. Investigation and Audit /
receipt buttons read the selected existing record. No JSON editing or extra
terminal is required. Scenario, approval and Self-Improvement Backend paths are
unchanged.

## 7. Investigation / audit

Research investigation summaries separate incident ID, source, validation,
uncalibrated model advisory, verified evidence references, assessment and the
WRITE_DENIED recommendation boundary. Audit summaries show actual UTC timestamp,
receipt/source type, model identity, artifact/input binding, stored outcome,
integrity and restored checkpoint/context. These are read-only projections of
existing receipts and existing governance validation, not new approval records.
Technical JSON is behind the existing details action. Copying a digest retains
the full 64 characters. The actual audit-view test confirmed the SQLite file
SHA did not change. Existing operational Authentication investigation remains
separate, labelled NATIVE_OS.

## 8. Responsive layout

Actual WSLg checks passed at 1920×1080, 1366×768 and 1280×720. Eight critical
states remain above the bottom of the viewport. Status/card horizontal canvas
bounds stay inside their allocated width, and the main content scrolls to
lower charts and details. Resize redraws measured points. Keyboard focus and
Tab traversal were checked. Korean, English and numeric text rendered with
zero missing glyphs using existing typography. Tk scaling 1.0 and 1.5 were
checked for status overflow; this does not certify every host/display DPI.

| Screenshot | Content / source |
|---|---|
| [Initial dashboard](final-gui-screenshots/initial-dashboard-1920.png) | Current preflight, no new inference, empty charts |
| [Dashboard 1920](final-gui-screenshots/dashboard-1920.png) | Actual native research results and retained Authentication |
| [Dashboard 1366](final-gui-screenshots/dashboard-1366.png) | Responsive two-row status ribbon |
| [Dashboard 1280](final-gui-screenshots/dashboard-1280.png) | Smaller viewport and scrolling |
| [Network research](final-gui-screenshots/network-research.png) | Two unique offline flows, Quality + Edge |
| [DNS research](final-gui-screenshots/dns-research.png) | DNS9 fixtures, actual LiteRT results |
| [Research investigation](final-gui-screenshots/research-investigation.png) | Source-bound scripted READ-only assessment |
| [Authentication investigation](final-gui-screenshots/investigation.png) | Retained verified NATIVE_OS investigation |
| [Audit](final-gui-screenshots/audit.png) | Validated research receipt and checkpoint |

Screenshot SHA256, dimensions and sanitized receipt evidence are recorded in
[final-gui-evidence.json](final-gui-evidence.json). No raw packet payload, model
binary, operator credentials or private home paths are included.

## 9. Actual WSLg / native evidence

The final WSLg run passed three tests: one-click actual artifacts, parent-crash /
worker-cleanup recovery, and actual module launch / duplicate launch / graceful
SIGTERM. The final GUI run invoked Quality twice, Edge twice and DNS twice.
All six records were COMPLETE / ASSESSED_READ_ONLY with restored checkpoints,
zero provider API calls and verified audit chain. Network scores were 0/1;
Edge approximately 0.00024273/0.99981719; DNS 0.55859375/0.0. These are offline
research results, not operating accuracy or new live attack detections.

| Artifact | SHA256 |
|---|---|
| Quality RandomForest | `53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603` |
| Edge scaler + LogisticRegression | `661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882` |
| DNS LiteRT DNN | `28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33` |

Closing/reopening preserved the same invocation IDs and counts with stopped
workers. Cached explicit replay returned the retained result with no new model
call. Four retained Authentication SQLite files were unchanged across the GUI
journey. This phase did not collect new journals or packets.

## 10. Security boundaries

NOT_INFERABLE, BLOCKED, WRITE_DENIED and RESEARCH_ONLY remain enforced by existing
Backend contracts. No automatic model promotion, registry insertion, new finding
promotion, response bypass or new write button. No Producer contract, model
artifact, raw dataset, capture permission or Runtime lifecycle implementation
was changed. No new capture, test network traffic, sudo, training or OS security
write was performed. Regression marker/test-directory effects are isolated
fixtures, not host security changes. Existing socket guard blocks AF_INET,
AF_INET6 and AF_PACKET during applicable regression runs.

## 11. Regression and independent export

Results are per execution; overlapping suites are not added together.

| Execution | Result |
|---|---|
| Working Runtime / network monitor / operational feature | 266 passed, 114.89 s |
| Working governance / GUI / research / scenario | 325 passed, 1 deselected, 239.87 s |
| Working investigation / execution / Self-Improvement | 491 passed, 886.51 s |
| Final working GUI + research focused | 143 passed, 37.90 s |
| Final actual working WSLg | 3 passed, 50.52 s |
| Working actual Fixture Queue chart | 1 passed, 14.00 s |
| Final export GUI + research focused | 143 passed, 33.17 s |
| Actual export WSLg | 3 passed, 46.17 s |
| Export actual Fixture Queue chart | 1 passed, 8.96 s |
| Export durable-execution isolated follow-up | 9 passed, 21.01 s |
| Unbound INET identity-denial test, separate | 1 passed, 0.32 s |
| Initial export core, with concurrent validation | 490 passed, 1 failed, 824.12 s |
| Serial full export core | 491 passed, 740.41 s |
| WSLg immediate-focus follow-up attempt | 1 failed, 2 passed, 18.26 s |

The first export core run failed in unchanged
`test_process_crash_recovery[side_effect]`: the child exited 0 rather than the
fixture's expected forced-death code 73. The retained isolated SQLite state had
only intent_created/claimed events, a **one-second test lease**, no invocation
timestamp and no effect marker. The test child catches ClaimConflict and exits
normally, consistent with the existing fail-closed expiry branch before dispatch.
The child did not preserve the exact exception text, so scheduler delay is an
inference, not a measured exception cause. No executor/lease/security rule or
unrelated test was changed. Its complete nine-test process/recovery suite passed
in isolation; its serial full export core rerun passed as recorded below.
The failed run is retained as a failure, not added to passed-run totals.

Final quality: SOC `ruff check src tests` PASS, full `ruff format --check .` PASS
(919 files), `git diff --check` PASS. Export Ruff check also passed and full
format passed for 875 files (the user/Replay files are absent). ML was read-only; its full format check
still reports 24 files requiring formatting / 121 already formatted. Those
pre-existing notebooks/docs/scripts are outside this GUI scope and untouched.
Broad working regression suites preceded the final presentation-only missing
validation-label correction; final working/export focused and WSLg runs use the
corrected source. The INET identity-denial case was excluded from the global
socket guard run and passed separately: it only creates/closes an unbound socket,
without bind/connect/send or network traffic.

Serial export core: **491 passed, 740.41 s**, without concurrent heavy suites.
The prior recovery test passed with unchanged code and security guards. This
resolves the scoped regression gate; the one-second fixture remains sensitive
to scheduling/resource contention and its first failure is disclosed above.

A later WSLg attempt failed before the one-click model demo: the test expected
focus immediately after a WM request, but actual `focus_get()` was still None.
The test now pumps the event loop until the real focus event arrives, with a
three-second deadline, then verifies button focus and Tab traversal. It does
not repeatedly steal focus, change product behavior, or accept a missing focus.
That failed execution is retained separately; final WSLg results above are from
the corrected synchronization.

The export contains baseline Git archives of SOC and ML plus only this phase's
allowlisted GUI source, tests, report, summary and images. User changes and
uncommitted Reliability Replay source are absent. An import-root assertion
ensures changed GUI modules load from the exported checkout. Existing pinned
local Python/native environment and digest-verified local model binaries are
explicit external test dependencies; they are not copied or reinstalled. The
existing test helper `research_paths` supplies exported ML source and pinned
artifact/runtime paths, with read-only environment preflight pointed explicitly
at the original pinned project environment. Readiness and inference results are
not mocked. Export is source reproducibility with these declared dependencies,
not a standalone deployment bundle.

Working/export actual native outputs, input/artifact identities, investigation
boundaries and checkpoint status agree. Actual invocation IDs are disjoint,
proving a fresh export run. Wall times, latency, receipt IDs and screenshot
pixels containing timestamps are expected to differ. Screens have the same
dimensions and pass the same state/count/bounds assertions.

Reproduction uses `.venv/bin/python -m pytest --import-mode=importlib` for
`tests/unit/gui`, `tests/integration/gui`, both unit/integration research-adapter
and DNS-research directories. Actual display checks use
`tests/gui_final_ux_checks.py`, `tests/gui_stabilization_checks.py` and
`tests/gui_wslg_checks.py::test_actual_module_command_duplicate_and_graceful_sigterm`
with existing native model paths and a read-only saved Authentication runtime.
`SOC_GUI_SCREENSHOTS` selects the image output directory and
`SOC_UNIFIED_AUTH_RUNTIME` selects that retained runtime. No privileged capture
command is part of this validation.

## 12. Remaining issues / final scope

This GUI phase does not certify physical Linux, a running collector's packet
visibility, new operational Producer parity, calibrated attack probabilities,
or deployment packaging. The actual Runtime used for screenshots is stopped;
live throughput is UNKNOWN rather than invented. DNS9 training Producer remains
unverified. Operational Network/DNS inference remains blocked. Model latency
bars are measured but not mutually equivalent benchmarks.

Small viewports intentionally scroll to secondary cards/details; arbitrary DPI,
every font installation and every window-manager theme are not certified.
The existing source status DTO is the authority; presentation cannot independently
attest collector liveness beyond that contract. Backend timeout/crash and audit
tamper semantics remain the existing UNKNOWN/fail-closed behavior.

**Final GUI readiness: VERIFIED** for the existing offline research / retained
Authentication demonstration and actual WSLg layouts. Operational inference
readiness remains BLOCKED / NOT_INFERABLE; this is not a live deployment claim.

The baseline ownership inventory contains 118 pre-existing SOC dirty/untracked
files and 10 ML files; their SHA256 values and initially empty indexes were
checked unchanged before staging. This phase changes seven GUI source modules,
two test files, this report, one sanitized evidence JSON and nine PNGs. No ML
commit is required.

No further GUI or AI feature expansion is included. The next stage is the final
E2E demonstration, report and portfolio evidence using these existing screens.

Selective task inventory: `gui/app.py`, `charts.py`, `components.py`,
`insights.py`, `presentation.py`, `research_view.py`, `unified.py` under
`src/soc_agent/`; `tests/unit/gui/test_final_ux.py`;
`tests/gui_final_ux_checks.py`; this report; `final-gui-evidence.json`; and the
nine images listed above. Existing README, pyproject, Command Center docs,
Runtime/Backend implementations, ML sources, artifacts and Replay are excluded.
