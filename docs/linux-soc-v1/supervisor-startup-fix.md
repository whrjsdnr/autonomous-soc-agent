# Release 0.5.5 Supervisor startup correction

The original qualification stopped before OS authentication with `RELEASE_TCX_PLAN_REQUIRED`. No Root installation, privileged inventory, Collector or Kernel resource was started. Historical evidence remains in `.git/native-supervisor-verification-055/`.

## Cause and correction

`supervisor_startup.execute()` passed `Preparation.plan` directly to `SupervisedSession`. This is the legacy B2A preparation plan. It bypassed the existing `Preparation.os_auth_handoff()` transition that binds the TCX object, TCX mode, release bundle and application scope.

Startup now calls that same factory with a mutually exclusive `supervisor_image` selector. The existing TCX transformation is reused without duplication. The strict Legacy plan rejection stays unchanged. Supervisor construction additionally requires the image namespace and lo/ifindex1/Ingress scope. Release approval still verifies the manifest and Bootstrap/Broker/Loader/TCX SHA tuple; application session/controller identity checks and resource wire encoding remain unchanged.

Before the approval prompt or sudo, startup verifies the image SHA, package/manifest/dependencies, current namespace, TCX plan and session, and the prepared Zeek source bundle. No password handling or privilege boundary was changed.

## Validation

26 focused tests passed in 35.72 seconds: five new cases run the real startup to the explicit approval boundary, or reject Legacy plan, namespace, manifest and image mismatches before authentication; the existing 21 Supervisor tests cover IPC/lifecycle boundaries. The successful preparation case checks TCX SHA, bundle, release, session, lo/Ingress, Zeek bundle and encoded 300s/4096/32/256MiB/20CPU-second limits. Authentication is replaced by a forbidden call in these tests, and approval is denied deliberately. Ruff, format and diff checks pass. These are unprivileged results, not Native authentication or capture success.

## Revised candidate identity

- Version: 0.5.5, **revised candidate; previous SHA approval does not apply**.
- Manifest: `092f4d91bbe6b9eea9f8dea72ba5435f1d3b86f1ffdeccd99c89f53ea4d58aad`
- Source bundle: `1a71e435ac461311aeaa8f1110ab54998b6ba0e5002dd12631e194680e98f7e8`
- Execution image: `54b1f365b835472f2594c7d264787aa3351004bdeec3582f9ff35f61fa17b960`
- TCX object: `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06`
- Zeek bundle: `8a422950144a7070610fc5d5e8b703efc19fcbd26f95d5c239b2374c233e257d`

All nine payload hashes are in [the evidence file](supervisor-startup-fix-evidence.json). Bootstrap, Broker, Loader and TCX binary hashes are unchanged; source-bound manifest.bin, release.json, release.trust and execution image changed. Candidate is private under `.git/native-supervisor-startup-fix/candidate/`; binaries and Native sessions are excluded from Git.

## Installation and approval

The Root-owned installed 0.5.3 release was verified read-only, with Manifest `5b135c3da785ea250664387b8e6e128412a0e260b8cc416d89118a30d84b8d19`. It has not been changed. Installation target remains `/usr/libexec/soc-agent-ebpf`; existing atomic update retains this exact release at `/usr/libexec/.soc-agent-ebpf.rollback-5b135c3da785ea250664387b8e6e128412a0e260b8cc416d89118a30d84b8d19`. That backup path is currently absent. Approved installation uses root:root, executable0555 and other files0444, no setuid/file capabilities. Rollback is an explicit later operation that must verify both releases and absence of active owned resources before restoring the retained directory; it is not automatic.

A new explicit approval is required for this candidate's installation and one Native session. Scope remains net:[4026531833], lo/Ingress, at most300s/4096 TCX events/Queue32/256MiB/CPU20s; passive Zeek separately observes the same namespace/lo under its existing Collector limits. One terminal authentication, no traffic generation, no automatic retry. The authenticated Supervisor must complete privileged Program/Map/Link and lo filter inventories before Attach, and refuse existing Links/uncertain ownership. No new privileged inventory has been performed in this task.

OS authentication, TCX packet counts, Network14 features, DNS counts, Clock/Loss, Drain and Native Cleanup remain NOT_OBSERVED/PENDING. The startup defect is corrected through the pre-authentication boundary; privileged operation is still unverified. Native AI, DNS9 and promotion remain BLOCKED.
