# Release 0.4.5: authentication-only STOP protocol correction

## Actual Native progress in 0.4.4

Root installation of 0.4.4 completed at 2026-10-21T00:01:18 UTC. All nine installed
file SHA/owners/modes/dependencies were verified; prior 0.4.2 and 0.4.3 remain archived.
An initial ordinary-user command wrongly referenced the old 0.4.2 artifacts, so
reference checking denied it before authentication. The command was corrected to
align installed release, package, artifact directory and source Bundle at 0.4.4.
No Root reinstall or Native retry was performed for that preparation-only failure.

Aligned session `13e82898-4ead-4bba-9cf1-940f67f8e094` then verified actual OS
fresh-auth qualification and Broker IPC handoff. Its audit records
OS_AUTH_HANDOFF_VERIFIED, BROKER_SESSION_BOUND, BROKER_READY and
OS_AUTH_QUALIFICATION_VERIFIED. /proc capability sets observed for this auth-only
Broker were Effective/Permitted/Inheritable/Bounding/Ambient ALL ZERO.
This proves the auth-only scope; Native capture capabilities remain unverified.
The Controller remained an ordinary UID 1000 process. No GUI was launched in B.

After the operator requested B stop, the Controller recorded HANDOFF_COMMAND_FAILED
and CLEANUP_UNVERIFIED. The entry process actually exited 0, but no valid STOP
acknowledgment was verified. We do not upgrade that cleanup result retrospectively.
No BPF load, TCX attach, packet data event or Native Network14 Feature occurred;
C was correctly withheld. Audit chain digest: `14d8d44d4c87baf6eb208a83205d68873a498ccf07abcda5bf92380d43a9244c`.
No existing audit or Native evidence was changed. No automatic retry occurred.

## Root cause and structural correction

The shared wire contract maps STATUS=3, STOP=5, CLEANUP=6. Python's auth-only
close sends STOP with USER_STOP, but the C auth-only loop mistakenly accepted
only operations 3 and 6, closed on operation 5, and returned 0 on that rejection.
The C allowlist now accepts exactly STATUS and STOP. CLEANUP and every Kernel
operation remain denied in this auth-only role. Malformed/replayed messages still
fail credential, sequence and schema validation. Rejections now return a nonzero
entry status rather than appearing as successful process shutdown.

The server sends the validated STOP reply, then waits for the Controller to close
its connected socket before exiting. This preserves the live PID/start-tick identity
while the Controller authenticates the final SCM credentials. The wait is bounded
to the existing five-second control interval and rejects additional commands or
trailing bytes. This is an acknowledgment/close protocol, not an increased timeout
or automatic retry. The Python close path also avoids duplicate close events after
a nested command rejection has already revoked and closed the session.

## Validation and release identity

The actual C serve loop was compiled and exercised over real ordinary-UID Unix
SEQPACKET sockets with kernel peer/message credentials. Tests cover STATUS→STOP→
validated reply→Controller close→process exit 0, process alive until final validation,
CLEANUP rejection, replay, partial frames, close-event idempotence and the existing
no-retry auth failure. Six cases passed. No sudo/PAM, privilege changes, BPF map,
load, attach or network traffic was used. Ruff/format/diff passed; artifacts compiled
and matched the current-source reference. Ordinary-user temporary-directory
install/check/rollback passed. None of this replaces Native B cleanup verification.

- New release: 0.4.5; destination /usr/libexec/soc-agent-ebpf.
- Manifest: `b65f1a8ad6365288ebcba9bc01bdbd14f740c5cc9ba6d7429271e05a22ef511d`.
- Bundle: `2b63f8d5dde9940c3704b7d1a7075c76e0e5de86768e03e6565a66af0e6d4981`.
- Installer SHA256: `935b5cf2d7ed88ca6fca90df4d2c5a07c78320d4404166273c3104272fd3cb37`.
- Exact update code SHA256: `36a098546bf40bedb1143c8276c63cfe4c1d2c3a9272dd79305a9e0b143a6f25`.
- Files root:root; executable files 0555, others 0444; directory 0755.

| File | Mode | SHA256 |
| --- | --- | --- |
| bootstrap | 0555 | `b7df9d2c462445ad96d02ca9eb8be6c5f5fb8df57349f88958413f13ca649b27` |
| broker | 0555 | `b872565bcd0abc67c2a5b9c7f96b21d9acb46df582870e303e067c42376254ff` |
| entry | 0555 | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | 0444 | `7905693372d14e93162ff7fbeea4068a0094a737663b2403c337630901706536` |
| manifest.bin | 0444 | `64816a049f49ae40c29a1c2884fb87ba3c8046fb512d41b616eb1c1a6103704d` |
| pam-policy.conf | 0444 | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| tc.bpf.o | 0444 | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| release.json | 0444 | `b65f1a8ad6365288ebcba9bc01bdbd14f740c5cc9ba6d7429271e05a22ef511d` |
| release.trust | 0444 | `1c7673a2f1655e6702f9c83ff65b54dfa4251af8e119ba39c274346686f421fe` |

Only Bootstrap and release metadata/Bundle change; Broker, Entry, Loader, TCX object
and reference PAM file remain byte-identical. Authentication and Kernel gates are
not relaxed. The installed 0.4.4 release is still intact; 0.4.5 is not installed.

## Proposed update and conditional retry — exact approval required

The fixed shell-free update argv is prepared in
`.git/tcx-c2-execution/v045-update-command-awaiting-approval.json`.
It uses the reviewed sudo -k → env -i PATH=/usr/bin:/bin LANG=C →
/usr/bin/python3 -I -S boundary and verifies both separately pinned installer images
through held O_NOFOLLOW FDs before executing either. It imports no project Python
as Root. Only the reviewed fixed nine-file installers may perform filesystem writes.

After exact file-set/owner/mode/SHA/quiescence checks, old 0.4.4 is atomically moved,
without deleting or overwriting files, to:
`/usr/libexec/.soc-agent-ebpf.rollback-b7ff46da0c38cc95cebc430a8eea012f8b3a326108fd1f0c415e8ca6bce25e7c`.
The new nine-file 0.4.5 release is then published with no-replace rename. Unknown
contents or destination/archive/staging conflicts fail closed. If publish fails,
stop with the old archive preserved; no B/C or automatic retry. Restoration needs
a reviewed recovery command. Earlier release archives are preserved unchanged.
No system PAM/NSS/sudoers file, shadow data, service, file capability, qdisc, filter,
model, dataset, Audit history or previous Native session is changed by installation.

Verify actual installed version, all payload SHA/modes/owners/dependencies, package,
artifact directory and source Bundle BEFORE starting B. Both next auth and live
argv were constructed directly for artifacts-0.4.5 and release-0.4.5, not by keeping
an older artifact argument. A fresh B session requires yes and OS terminal password,
then a successful STOP acknowledgment, process exit and authorization disposal.
Only afterward may one fresh C session start within the previously approved scope:
lo, current verified net:[4026531833], INGRESS, 300 seconds, 4096 events, queue 32,
256 MiB address space, 20 CPU seconds. Preserve existing filters/links, no raw payload,
no test traffic, no packet blocking/modification, no pinning or automatic retry.
No root GUI or AI worker is authorized. A failure stops C and further attempts.
Native AI, DNS9 and operational promotion remain BLOCKED.
