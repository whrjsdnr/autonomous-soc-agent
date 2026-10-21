# Native entry error preservation and next Live qualification

## Historical failure and evidence limits

Installed release 0.5.5 has Manifest `092f4d91bbe6b9eea9f8dea72ba5435f1d3b86f1ffdeccd99c89f53ea4d58aad`. The failed session is `cd66c0da-8fce-4c8a-a861-0bb342f7be2c`, preserved under `.git/native-supervisor-startup-fix/candidate/session/` and `.git/native-supervisor-verification-055-fixed/`. One sudo request reached Root installation; Broker Handoff did not complete. The entry returned1 and the Controller reported `AUTH_QUALIFICATION_ENTRY_REJECTED`. Original Root stderr was terminal-only. Its actual API, errno and underlying refusal remain UNKNOWN. No password failure, capability shortage or Verifier refusal is inferred from this wrapper error.

Current installation and the preserved 0.5.3 rollback payloads were verified read-only by SHA, ownership and modes. Fixed bpftool/tc trusted-file checks and an ordinary-user Docker `/version` query passed; API1.52/min1.44 includes the pinned1.51. Ordinary-user inspection of the Root daemon namespace returned EACCES; this is a separate read-only observation, not evidence of the earlier Root failure. No privileged inventory, authentication, installation, BPF load, attach, capture or traffic was performed in this remediation task.

## Confirmed diagnostic causes and changes

1. `authenticate_native()` attaches sudo stdin/stdout/stderr to the OS terminal. Its pre-Handoff wait sees only child exit, losing the Root error in persisted evidence. Terminal/password handling stays unchanged.
2. Python `Popen(preexec_fn=...)` generalizes a preexec Capability-setting exception to SubprocessError. Fixed inspection helpers now emit the original OSError errno before rethrowing. No capability requirement is relaxed.
3. The reviewed Root Supervisor preparation now emits bounded structured stage/code/actual errno on failure. Stages distinguish Program/Map/Link/ingress/egress inventory, Docker preflight and sidecar preparation. It rethrows the original exception and never retries.

A separate abstract SEQPACKET diagnostic endpoint is session-bound and created before sudo. Controller checks Kernel SO_PEERCRED root UID/GID, bounded1024-byte schema, rejects ancillary FDs/truncation, and writes an exclusive0600 private `entry-diagnostic.json` plus an append-only application Audit event. Only diagnostic enum fields and actual OSError errno are retained; no raw stderr, traceback, password, approval envelope, authentication token or command string is stored. Cleanup closes the diagnostic listener even when no report arrives.

**This is advisory failure evidence, never an authentication or authorization receipt.** Root peer identity alone does not establish Broker process/session readiness. Existing Broker PID/start-ticks, approval/Manifest scope and capability checks remain authoritative. A missing/untrusted diagnostic leaves the original error and Native Cleanup unverified; it cannot enable Capture. Later owned-Link Cleanup remains on the existing path. Helper diagnostic reporting is disabled for post-start queries so entry evidence cannot falsely attest later Cleanup.

Scope limitation: this reports errors in Supervisor preparation and its preexec helper; sudo failures before image entry or C Bootstrap rejection after exec still use existing error evidence and may remain UNKNOWN. It does not recover historical stderr or prove historical Kernel Cleanup. Parent-side preexec SubprocessError remains unchanged, while its original child errno is separately retained.

## Verification

33 targeted tests passed (38.61s), including the actual startup before approval, existing Supervisor IPC/cleanup boundaries, and seven new diagnostic cases. New cases cover successful private persistence with explicitly simulated Root credentials, ordinary peer rejection, malformed/secret-shaped evidence rejection, false authority claims, original exception preservation/no retry, exception-text omission and preexec errno preservation. These fixtures invoke no sudo, capset, BPF or capture. A focused seven-case run also passed; the final 33-case run covers the finalized source after excluding post-start failures from pre-entry diagnostics. Ruff/format/diff are checked on changed files only. No GUI/model or broad regression was repeated.

## Release 0.5.6 candidate

- Manifest: `6a709a4c24f461c4e1de996a8eb9e32a4928340720c93f2141615af6f521deb9`
- Source bundle: `ee1cfd5e5c3499fbc8f839207e7c956430487f51933eb40d2941f1de0eb72a40`
- Execution image: `3216c80bf6f99cf92912bbff9fcb89ba1ba51e4d0c27205d08d0e7da2741f8e2`
- TCX object: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`

All nine file hashes and installed permission contracts are in [the evidence](native-entry-diagnostic-evidence.json). Native Bootstrap/Broker/Loader/TCX binaries are unchanged; Python supervision, manifest binding and image changed. Candidate is private under `.git/native-entry-diagnostic-056/final-candidate/`. Existing Native sessions and model/data artifacts are excluded from Commit.

## Next approval and safety conditions

New SHA requires explicit approval. Proposed operation: preserve installed0.5.5 at `/usr/libexec/.soc-agent-ebpf.rollback-092f4d91bbe6b9eea9f8dea72ba5435f1d3b86f1ffdeccd99c89f53ea4d58aad`, atomically install candidate0.5.6 at `/usr/libexec/soc-agent-ebpf` (root:root executable0555/other0444), one fresh terminal OS authentication, then mandatory read-only Kernel inventory. Keep the already retained0.5.3 unchanged. The new backup path is absent, so no existing rollback is overwritten. Rollback requires explicit identity/resource checks and is never automatic.

Prior privilege processes must be gone. Before any BPF Load/Attach, the same authenticated Supervisor must verify Program/Map/Link/lo-filter inventories; failed query, existing Link or ambiguous ownership blocks Capture. No resource is deleted to make this pass. Only after these checks and successful scoped Handoff may the single approved run proceed on net:[4026531833], lo/Ingress, <=300s, <=4096 TCX events, Queue32, AS256MiB, CPU20s, passive Zeek on the same lo with its existing separate limits. No traffic generation, interface expansion, pinning or automatic retry. GUI/Network14/DNS adapter/model workers stay ordinary-user. AI, DNS9 and promotion remain BLOCKED.

At this handoff point Live E2E remains incomplete: TCX packets, Network14 features and DNS Query/Response were not observed; Native Drain, final Kernel inventory and Cleanup remain PENDING/UNKNOWN. Do not replace those results with fixture counts. After a newly approved attempt, preserve the first actual error, stop/clean both Collectors independently, and use the resulting new evidence for the next minimal remediation.
