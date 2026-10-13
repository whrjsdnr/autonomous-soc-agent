# Original Gate C: common real-time pipeline

2026-10-13. Existing SOC Integration / Platform Validation tags retain their original meanings.

`python -m soc_agent.realtime` is the new bounded polling entrypoint. DESKTOP and SERVER
use existing `compose_application`, offline scripted planner/assessor, actual SOCRuntime,
Policy/Approval/Execution Guard, checkpoints and explicit isolated RuntimeGovernanceStore v16.
Windows SERVER is rejected. This is an offline controlled execution mode, not a live LLM service.

```text
journald / Windows Get-WinEvent (System metadata only)
 -> CommonEvent v1 -> private SQLite queue + cursor transaction
 -> claimed worker -> retained source Evidence -> existing SOCRuntime
 -> scripted Investigation / Assessment / Decision / human boundary / checkpoint

explicit synthetic precomputed CommonEvent fixture
 -> same queue / worker -> official external predictors
 -> official Envelope / existing typed validation / External Context v2
 -> existing protected SOCRuntime / receipt / audit / checkpoint
```

Native OS metadata does not contain Network Top40 or DNS9. It therefore takes the
NOT_INFERABLE branch: no feature fabrication or model invocation. Explicit fixtures
retain the existing synthetic-only DerivationProvenance. No production feature extractor
or real network/DNS feature assurance has been invented. Quality/Edge share one source
observation; DNS remains distinct; no probability averaging or risk score addition.

Queue SQLite is separate from runtime SQLite. They do NOT share a transaction.
Runtime publication precedes queue DONE acknowledgement. Replay uses stable incident/source
IDs, checks retained content and restores checkpoints; existing external context prevents
reinference. Interrupted context publication remains fail-closed and may need reconciliation.

Only a bound source-report READ tool is registered. No security WRITE handler, human authority,
provider or HTTP listener is configured. Existing context capabilities and core governance
remain enforced. This is trusted application composition, not an OS sandbox for hostile Python.
Existing `soc_agent.desktop` / `external_runtime` / API commands are unchanged; the new
collector CLI composes their shared runtime instead of changing legacy invocation contracts.
