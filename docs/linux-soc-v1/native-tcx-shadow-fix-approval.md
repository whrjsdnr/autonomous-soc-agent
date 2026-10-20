# Release 0.4.4: shadow-file trust correction and retry approval

## Actual 0.4.3 outcome

The approved 0.4.3 update completed successfully. All nine installed files, modes,
root ownership and dependency/Manifest integrity were verified. Exact 0.4.2 remains
preserved in its manifest-named rollback archive. B session
`68574dd4-35f5-4f4e-82eb-cb7bde0bd87e` accepted yes and passed the corrected real TTY
check. OS_AUTH_REQUESTED was audited. The fixed sudo command subsequently exited
before Broker handoff: AUTH_QUALIFICATION_ENTRY_REJECTED. C was not attempted.

Read-only /var/log/auth.log correlation found the fixed Bootstrap command and sudo
PAM session open/close entries for this attempt. No unrelated log content or password
was copied. This demonstrates OS execution of the fixed entry, not full application
fresh-authentication/IPC/capability qualification. Broker handoff is still unverified.
The existing generic error does not identify the first internal policy branch.
The app Audit chain was verified read-only; ordinary app cleanup completed, while
its privileged handoff cleanup status remains CLEANUP_UNVERIFIED. No BPF load,
TCX attach or owned Link was reached. No automatic retry was performed.

## Proven blocker and minimal correction

`policy()` reads /etc/shadow through generic soc_trusted(). That function requires
GID 0 for all files. This system's normal /etc/shadow metadata is UID 0, GID 42
(root:shadow), mode 0640. It therefore deterministically rejects this required file
if the policy reaches that branch. We do not claim the old generic error proves
this was the very first runtime branch; other strict OS policy checks remain.

The fix special-cases ONLY the literal /etc/shadow read. It walks trusted Root and
etc directory FDs with O_NOFOLLOW, requires root ownership and immutable-to-other
parents, then checks a single regular root-owned file with EXACT mode 0600 or 0640.
The file's group is allowed read access under the existing OS policy, never write.
Symlinks, hardlinks, non-root ownership, group write and world read remain rejected.
No NSS name lookup or shadow content is emitted. Generic binary/library trust is
unchanged. The held FD is compared before/after reading for inode/device/size,
owner/group/mode/link count/mtime/ctime consistency; the password-file buffer is
explicitly cleared after checking that a local password hash exists.

Fixed secret-free stage labels now distinguish sudoers policy, included policy,
shadow-file trust, local password requirements and sudo parent/fresh-command checks.
They never echo policy lines, password hashes or input. Python receipts additionally
preserve the OS entry exit code. No sudoers/PAM/NSS configuration, shadow content,
password, group membership or permission is changed by this fix.

## Validation

Eight compiled C metadata fixtures and two targeted auth/no-retry/sudo-policy
regressions passed (10 total). They never open the real shadow file or authenticate.
Both allowed modes and forbidden owner/modes/hardlink/device/symlink cases are covered.
NOPASSWD and authentication exemptions remain denied. Ruff/format/diff passed.
The current-source Bootstrap/Loader/Broker/TCX artifacts compiled and were packaged;
reference compilation verified them. An ordinary-user temporary-directory
install/check/rollback simulation passed. None of those results is Native proof.
No full GUI/model regression, screenshot or performance run was repeated.

## Exact new release scope

- Release: 0.4.4, destination /usr/libexec/soc-agent-ebpf.
- Manifest: `b7ff46da0c38cc95cebc430a8eea012f8b3a326108fd1f0c415e8ca6bce25e7c`.
- Source Bundle: `a916c6cdfb7403e4d12fa2fe41d1cb4d0a13eaf6141dadf12ee4d2e12babc3fe`.
- Installer SHA256: `35581f3fc03b00c8d5edffe27ffa4f81eaea45fc95be9c6d937224a1438cd07b`.
- Exact update code SHA256: `7808a4149c5e3ac1c8407e8eb0d4d347d3d8c0cfe4052772019bfd30f667b40d`.
- All files root:root, executable files 0555, other files 0444; directory 0755.

| File | Mode | SHA256 |
| --- | --- | --- |
| bootstrap | 0555 | `920fac8adb74714352b81a3148270dc457e6a086e3772966337eded5bf694eb5` |
| broker | 0555 | `b872565bcd0abc67c2a5b9c7f96b21d9acb46df582870e303e067c42376254ff` |
| entry | 0555 | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | 0444 | `7905693372d14e93162ff7fbeea4068a0094a737663b2403c337630901706536` |
| manifest.bin | 0444 | `fa16b9e32a151ffab695adfd6ad968abe0a8c3b72553b01655081c2dcdb9bb5f` |
| pam-policy.conf | 0444 | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| tc.bpf.o | 0444 | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| release.json | 0444 | `b7ff46da0c38cc95cebc430a8eea012f8b3a326108fd1f0c415e8ca6bce25e7c` |
| release.trust | 0444 | `73560f0f19aeea5d5f72a35e36272cdc73b40e99d573a639455e1bae208cede3` |

Bootstrap bytes change for this fix; Broker, Entry, Loader, TCX program and PAM
reference bytes are unchanged. The installed 0.4.3 release has not been modified.
The existing 0.4.2 archive is preserved as well.

## Proposed Root update and failure boundary — not executed

The fixed shell-free argv is prepared in
`.git/tcx-c2-execution/v044-update-command-awaiting-approval.json`.
It uses /usr/bin/sudo -k, /usr/bin/env -i PATH=/usr/bin:/bin LANG=C,
and /usr/bin/python3 -I -S with fixed SHA-pinned code. Both installer images are
read through held O_NOFOLLOW FDs and their exact SHA/Manifest values are checked
before any filesystem mutation. No project code is imported as Root.

The old reviewed engine first verifies exact 0.4.3 files/SHA/owners/modes and
process quiescence and atomically unpublishes that release, without deletion, to:
`/usr/libexec/.soc-agent-ebpf.rollback-2bcd28ef47e2ce75539117d72f7e1eed9d6b4408a2ca8026a00df3bd86815452`.
The new engine atomically publishes only the nine approved 0.4.4 files without
overwriting existing paths. Unknown contents/archive/staging conflicts fail closed.
No Hook or external filter is removed. If publication fails after unpublication,
stop with the old release retained; do not continue B/C or automatically retry.
Restoration requires a reviewed recovery command. No service or root GUI starts.

## Conditional retry scope

The user requested correction followed by retry. Root installation of this new
Bootstrap/SHA needs its own exact-release approval under the original instructions.
After that approval: update, verify installation, one fresh B attempt with yes and
OS terminal password, verify stop/session disposal; only then one conditional C.

C remains lo, namespace net:[4026531833] rechecked, INGRESS only, maximum 300 seconds,
4096 metadata events, queue 32, address space 256 MiB and CPU time 20 seconds.
No raw payload, traffic generation, packet blocking/modification, Link pinning,
foreign Link/filter deletion, automatic retry, Native AI, DNS9 or operational
promotion is authorized. Kernel support/capability/Native cleanup remain unverified.
If B fails again, record the new fixed stage code and stop C. A successful sudo
password alone does not prove Broker handoff or authorize broader Root execution.
