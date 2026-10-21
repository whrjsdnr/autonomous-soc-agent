# Zeek integrity and Supervisor control shutdown remediation

## Baseline and evidence

Baseline `d52217f2efa4f8d64a89a9f7dbf4b2d5ff59ae8c`. The private
`.git/native-e2e-remediation-campaign-059/attempt-5/verification.json` records the
approved 0.5.13 Native run: TCX Program 5245 / Link 6, 4,096 packets received and
accepted by Network14, zero socket-send failures and queue rejections. Ring,
processing and Audit drains succeeded. Map/Link/lo filters were absent afterward;
existing foreign Programs were unchanged. These historical records are untouched.

Zeek persisted 3,843 packet records and ten network events, with no DNS event or
CLOSED. Its receipt reports `STREAM_PROTOCOL_FAILURE`, exit code 0 and successful
owned-container removal. Exit 0 alone proves neither protocol completion nor
capture integrity. Eight port-53 metadata candidates do not establish completed
DNS transactions. Query/response counts and visibility remain UNKNOWN.

## Root causes and limits of the evidence

`StreamProcess.run` normalizes exceptions using `safe_code` before persisting its
exit receipt. Unrecognized symbolic errors and validation errors become
`ZEEK_LIVE_INTEGRITY_FAILED`; the original failing record/API is unavailable.
The historical first Zeek failure therefore remains UNKNOWN. No retry or offline
fixture can reconstruct the missing input.

`Handoff.command` similarly replaces send/receive/schema/pump failures with
`HANDOFF_COMMAND_FAILED` before recording their original exception/errno.
The exact historical control failure is also UNKNOWN.

There is a reproducible structural shutdown hazard: startup waited up to 20s for
DNS work, then stopped the adapter, before closing the native handoff. The Broker
requires a request heartbeat within 15s. GUI refresh was the GUI-mode heartbeat
owner, so GUI delay and collector teardown could expire a healthy Broker. This
code-level hazard is established; attribution of the old run to ETIMEDOUT is not.
No synthetic error is relabeled as an actual syscall errno.

## Changes

* Preserve the first failure's Stage, API, exception class, allowlisted symbolic
  code, errno, subprocess return code, stream sequence, CLOSED state and observed
  container exit code before normalization. Bounded explicit cause chains retain
  wrapped OS errors. Validation types are retained without input values/messages.
  Arbitrary exception text, command arguments, addresses and secrets are redacted.
* Retain control send/receive/pump failures and request identity in snapshot and
  append-only Audit. Diagnostic Audit failure cannot bypass authority revocation
  or owned-FD cleanup and cannot yield a verified cleanup verdict.
* A session-owned heartbeat continues independently of GUI refresh and DNS task
  completion. One outstanding control job is allowed; packet queues remain 32.
  Request allocation, exchange and close are serialized by one reentrant lock.
* Request native/Supervisor cleanup before waiting on user-side DNS completion.
  Native close, DNS stop and DNS drain are attempted independently, preserving
  partial failures. Root Inspector and existing owned-container cleanup remain
  unchanged. CLOSED absence is never normalized to successful finalization.

No TCX observer, packet ABI, Network14 preprocessing, model, DNS analyzer or GUI
layout is changed. TCX_NEXT(-1), no pinning, no foreign removal and no automatic
reattach are preserved. NSS/PAM policies, capabilities and approval gates are not
relaxed. The source manifest changes and requires a new SHA-pinned Native approval.

## Verification and release

Related tests exercise missing CLOSED, malformed stream/decode failure, Docker OS
error wrapping, partial cleanup, control receive errno, concurrent status requests,
GUI-independent heartbeat and shutdown ordering. Test results and the exact 0.5.14
candidate identities are recorded in the private qualification receipt. Fixture
success is not Native verification. No authentication, Root install, BPF syscall,
TCX hook, capture, generated DNS traffic or privileged inspection was performed.

The installed 0.5.13 release is preserved. The proposed update retains its exact
nine files as rollback under the existing digest-specific atomic-install contract;
no installation is performed during preparation. The old campaign remains 5/5.
A separate proposal starts with zero attempts and requires explicit release/SHA
approval before any reservation or OS authentication.

## Remaining blockers and Native approval

Zeek normal CLOSED, DNS transaction visibility and whole-session cleanup require
new Native evidence. Overall Native E2E remains BLOCKED. Do not treat TCX data-drain
success as proof of Zeek completion or of total packet delivery: the old counter
emitted 4,119 events but delivered 4,096 at the cap. Clock calibration and flow
eligibility remain conservative.

Proposed new budget: at most three installations and three Native runs, each
separately bound to its exact release identity; no automatic retry. Scope remains
`net:[4026531833]`, lo/Ingress, 300s, 4,096 metadata events, queue32, privileged task
256MiB/CPU20s, passive Zeek in the same namespace/lo under its existing resource
profile. No traffic generation, interface expansion or capability expansion.
Native AI, DNS9 and operational promotion remain BLOCKED.

## Prepared Release 0.5.14 identity

| Item | SHA256 |
| --- | --- |
| Manifest | `b599d82b0cf444c462ec82f13e891d6b40e8e2def9a36f54dd8f6073b3623cc7` |
| Bundle | `4efa34bf659b64d4737d6b1c90188e0d38f70a74312a66562a673cbcf1cef564` |
| Execution image | `3328233556bfab9e1eeb5a2b96ce48948de196300ce08f523af039ca86d0f726` |
| TCX object | `9a4d26cfc3b09ac4635972f8559006d735aa3bc3da0cb09028b3ce53ae5fde06` |

These are prepared candidate identities, not an installation or execution approval.

Related verification passed: 62 focused lifecycle/control/startup tests; final stream-stage checks (41 tests), final control checks (5 tests), and independent source Export startup/stream checks (53 tests). These overlap and are not a total regression count. Ruff, formatting and diff checks passed. The exact final candidate also reached the expected approval boundary with authentication forbidden. Native execution remains pending.
