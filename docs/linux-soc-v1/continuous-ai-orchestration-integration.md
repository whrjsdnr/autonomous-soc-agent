# Continuous AI investigation integration

This change connects Continuous results to the existing `ApplicationService` and
`SOCRuntime`. It does not introduce a second orchestration engine or grant Native,
model, response, or API authority. The four fixed roles are Network, DNS,
Authentication, and Investigation.

## Operational path

```text
Continuous Collector / persistent input queue
  -> AnalysisService -> analyze-offline --defer-investigation
  -> verified OfflineWorkflow result and existing model receipts
  -> immutable InvestigationSource / evidence revision
  -> existing EventQueue (separate investigation queue)
  -> ApplicationService -> SOCRuntime durable step claim
  -> InvestigationPlanner / AdaptiveInvestigationPlanner
  -> InvestigationOrchestrator -> governed read-only retained-source tool
  -> ThreatAssessor -> existing response / policy / human-review boundary
  -> core checkpoint + trace + service Audit -> GUI
```

Native DNS transaction metadata can enter the same source adapter without DNS9
inference. Authentication windows use the existing compatible IF model path.
Collectors never await an LLM response. A separate asynchronous consumer processes
investigations; the existing Runtime supervisor owns its lifetime. GUI detachment
has no ownership of the service.

## Reuse and boundaries

| Component | Reuse |
|---|---|
| ApplicationService / SOCRuntime | Start, step, CAS checkpoint, durable claim, bounded rounds, policy/human transitions |
| InvestigationPlanner | Validated initial read-only plan |
| AdaptiveInvestigationPlanner | Conflicting model evidence and bounded distinct follow-up after a failed read |
| InvestigationOrchestrator | Existing governed read execution, evidence conversion and failed/blocked distinction |
| ThreatAssessor | Structured assessment with source evidence references |
| EventQueue | Durable task references, identity deduplication, claim tokens, recovery and completion |
| Existing model selection/fusion | Analysis retains its existing RF/LR comparison and authentication/package fusion; no new model execution |
| SecurityAISelector | Not used to select additional models in post-analysis investigation: an empty AI registry prevents unapproved model actions |

`ContinuousInvestigationPlanner` is an adapter of the existing planner, not a
workflow engine. `InvestigationTasks` stores source links and queue references;
SOCRuntime alone owns investigation transitions.

## Correlation, priority and recovery

- Original Incident IDs, model/feature fingerprints, Window/Flow references and
  original result hashes are preserved. Related Incident IDs remain distinct.
- Correlation requires matching target, scope, namespace, origin, clock and
  one-minute event-time bucket. Missing/unknown identity or clock stays standalone.
  Kernel monotonic timestamps are **not** relabelled UTC to join DNS/journal data.
  Adjacent time buckets and unproven cross-clock sources remain separate.
- Sorted immutable source hashes identify an Evidence Revision. A new revision
  creates a distinct task and checkpoint database while retaining the original
  owner Incident ID. Older tasks are marked SUPERSEDED; their evidence is retained.
- Existing EventQueue handles claim tokens and duplicates. Priority is a bounded
  deterministic rank (0–2): conflict first, unknown/model/collector errors next.
  Structured AI priority is recorded as advice, not execution authority. At most
  eight newer arrivals can overtake an older ordinary-priority task.
- Existing core limits allow at most two investigation rounds. Failed read-only
  tools may request a distinct follow-up; policy-blocked actions cannot use this
  path. Canonical attempted inputs cannot be executed again.
- A saved unclaimed checkpoint resumes. A crash during a claimed external step
  stays blocked for explicit review; recovery never steals that core claim or
  repeats an uncertain LLM/tool invocation.
- Queue pressure retains immutable source records for later scheduling. Source
  publication precedes Audit and task publication; recovery repairs a missing
  source Audit record before admitting a task.
- Archive requires stopped/verified cleanup and no pending/claimed investigation.
  Sources, task queue and core checkpoint databases are preserved. Restore creates
  every directory ancestor with private permissions; no existing Audit is erased.

## AI and error handling

Default Continuous investigation is explicitly **SCRIPTED**, using the existing
local desktop client plus structured coordination/replanning drafts. There is no
API key discovery, implicit external provider, or API fallback. An injected client
uses the same validated interface, but requires separate deployment/API review.

Planning context contains model advisory, source provenance, classification and
original failure reasons. Recommendations are not observations or approvals.
LLM-generated observation promotion is rejected. Additional models, Root commands,
new capture, service changes and response execution are unavailable to this adapter.

Known-error read-only revalidation remains in OfflineWorkflow. Its outcome and
limits enter investigation context. Unknown errors receive a read-only plan and
assessment. Timeout/invalid proposal/claimed-step uncertainty is retained as a
failure or human boundary; it cannot trigger privileged recovery.

## GUI

The existing Continuous screen displays task ID, fixed roles, priority, Evidence
Revision, state and waiting reason. Details include bounded decisions, worker
heartbeat, source origins, related Incident IDs and Audit references. The existing
Investigation view receives the verified core checkpoint's plan, assessment,
retained-tool evidence and recent trace. Full evidence stays in core storage.

Source origin and provider mode remain separate: a Native source with SCRIPTED
investigation is never described as an actual API investigation. Source-role
`EVIDENCE_RETAINED` is not a claim that its collector is currently RUNNING.

## Use

Existing commands remain unchanged:

```sh
soc-agent setup --home /absolute/new/app --replay /absolute/stored.pcap --ml-root /absolute/ML
soc-agent start --home /absolute/new/app
soc-agent status --home /absolute/new/app
soc-agent gui --home /absolute/new/app
soc-agent stop --home /absolute/new/app
```

Use a new ordinary Replay directory for development. Attaching this new code to a
previous Native runtime does not carry forward that runtime's approval or code
identity. Do not reset its identity file or reuse its receipts.

## Verification record

Operational code commit: `143c1e6524c8720c408d9240603f10b986a9436b`.
Code tree: `9b7714240c5582d366666affbf30d5d1e3299c8b`.

| Verification | Result |
|---|---|
| Workspace related regression including real Tk | 725 PASS, no skips |
| Independent Git Export plus exact change overlay | 725 PASS, no skips |
| Controller/READY/R1/R2/Namespace/Python boundaries | 127 PASS in Workspace and 127 PASS in Export |
| New orchestration/source/recovery tests | 28 PASS (included above) |
| Actual stored PCAP through CLI/real RF-LR/GUI | 128 source records; 6 Predictions; 3 Incident outputs; Audit verified |
| Three-domain fixture paths | Actual RF/LR 2 + IF 1 Predictions; DNS transactions with DNS9 inference blocked |
| GUI | Dashboard, Continuous, AI Analysis, Investigation, System; detach/reconnect; original service preserved |
| Stop | Owned ordinary Runtime Cleanup VERIFIED; unfinished input queue preserved explicitly |
| Pending investigation recovery | Isolated copy: DONE2/PENDING1 -> DONE3; same Task IDs, no new model or API calls |
| Native reproducibility | Six Continuous files identical across two builds and independent Export |
| Existing Supervisor / TCX compilation | Eight Supervisor outputs identical twice; TCX object identical twice; no Kernel load |
| Wheel | Two builds and independent Export identical |
| Ruff / format / diff | PASS |

The full suite includes the existing 5,000-event durability and multi-hour virtual
event-time tests. These are not claims of long-running Native operational stability.
CLI Stop preserved 33 pending analysis inputs and one pending investigation; it did
not report that those jobs had been processed. The investigation was then recovered
in a separate copy, preserving the original. All three final investigation tasks
were WAITING_HUMAN for independent evidence; their queue delivery was DONE. This
means a governed pause, not a verified threat or remediation.

Failures resolved during validation:

- Archive restore created intermediate directories with default permissions;
  it now creates every restored ancestor privately and rejects pending investigation
  archival. Source/core Audit and checkpoint validation remain enforced.
- Immutable source publication could precede its Audit across a crash; scheduling
  now ensures the source Audit exists idempotently before creating a runnable task.
- GUI only projected the old Offline investigation record; it now links the new
  core checkpoint's assessment, plan, evidence and trace to the original Incident.
- The isolated worktree test initially supplied the wrong research interpreter
  path. The existing explicit validation-root environment setting corrected the
  test environment; the production interpreter identity check was not relaxed.
- New fault tests were corrected to inject failure at the read handler boundary,
  retaining the actual Tool exception normalization and governed replanning path.

Artifacts (development evidence; none conveys execution approval):

- Wheel SHA256: `05288693b3a23b363e0e51decb29a1049a0a54553ffad2f79d65a46d68f94bbd`.
- Git source archive SHA256: `306c8ffd32da7668eb12d1a0d287c2437846b116ec6315c178d962568b85725c`.
- New candidate Root manifest SHA256: `b69c8d6e72aa34d16ebe67aa4dca76706968723195b701761d8245b6970e294b`.
- Runtime Session: `7454b157-57b5-4437-b053-735590e638ea`.
- DNS Session: `0fa031dd-6092-4d40-871c-7adbdc5952d2`.
- Ledger: 81 rows; SHA256 `07b3aa67d19e2c020f57dba9eb7b3d44bb7c86783cd5b91547f5c353f14f80ae`.
  All 3,038 pinned files of the previous review remain unchanged.

Evidence directory in the shared Git common directory:
`.git/continuous-orchestration-integration-20261030T073539Z/`.
It contains test logs, build manifests, CLI/GUI evidence, copy-recovery evidence,
`verification-final.json`, source snapshot, and
`native-review/approval-package.md` with an unapproved exact candidate binding.

**ORCHESTRATION_INTEGRATED** applies to implementation and nonprivileged verification.
Actual Native orchestration and external-provider investigation are not newly
verified. Preserved Native success/failure evidence and past UNKNOWN/UNVERIFIED
cleanup findings retain their original meaning.

Next limited trial proposal: existing namespace `net:[4026532232]`, lo/Ingress,
whole envelope <=600s, existing owner STOP400/Drain460, TCP<=4 connections,
DNS UDP2/TCP1, no automatic retry. The candidate lists eight fixed Root paths
(seven changed config contents, unchanged Collector executable), new Runtime/DNS
Session and fresh Source binding. It remains uninstalled and unstarted. Renewed
policy validity, new exact R1/Root/Native/DNS decisions and existing launcher binding
checks are required before Scope confirmation/sudo. Model Action and external API
are excluded from this proposal.

Native live execution is independently BLOCKED pending new exact Source/Artifact,
Session, policies, R1/Root/Native/DNS approval and direct Scope confirmation/sudo.
Model Action remains separately required for each eligible retained Native job.
The previous short test's remaining policy validity cannot meet its 65-minute
admission condition, and its receipts do not authorize this changed Source binding.
