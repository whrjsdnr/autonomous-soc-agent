# Native terminal ownership fix and Release 0.4.3 approval

## Verified failure and correction

The short-confirmation B session `114b197e-54f9-4545-8171-cefee3849574`
accepted the operator's yes, then failed with AUTH_QUALIFICATION_TTY_REQUIRED,
before OS_AUTH_REQUESTED, sudo execution, privileged Broker startup or Kernel work.
The expected user-owned terminal was incorrectly checked using `fstat(/dev/tty)`.
That inode is the system alias (root-owned, device 5:0); the actual /dev/pts terminal
belongs to the user. Password entry was never reached; this is not a password timeout.

The fix holds the controlling-terminal FD and a duplicate of terminal stdin,
checks actual stdin ownership and character-terminal type, compares the kernel's
TIOCGDEV real device against held stdin st_rdev, and checks both foreground process
groups. Pipe input, mismatched UID, background and missing controlling terminal
remain denied. No symlink/path reopening of the user's PTY is needed. The held
controlling FD is passed only to the existing fixed OS authentication command.

[Linux v6.18 tty_io.c](https://github.com/torvalds/linux/blob/v6.18/drivers/tty/tty_io.c)
returns new_encode_dev(tty_devnum(real_tty)) for TIOCGDEV; the installed ioctl header
uses _IOR('T',0x32,unsigned int). Device IDs are decoded using the Linux encoding.
Five real ordinary-user PTY cases, the existing auth-failure/no-retry case and six
scope-confirmation cases passed (12 total). Ruff/format and diff checks passed.
No OS authentication, capability change, network traffic, BPF load or TCX operation
was used for these tests. The installer install/check/rollback simulation also passed
under an ordinary user's temporary directory; this is not a Root installation result.

## Why an installation approval is needed

The corrected auth_session.py is included in the declared source Bundle. Keeping
the old Bundle while executing changed source would misstate release provenance.
Release 0.4.3 therefore updates manifest.bin, release.json and release.trust. The
Bootstrap, Broker, Loader, Entry, TCX object and PAM reference bytes are unchanged.
The installed 0.4.2 release has not been changed or removed.

The user's approval applies to one exact new release update, followed by one new B
attempt and conditional C, subject to the existing stage checks and no automatic retry.
This proposal is prepared and has NOT been executed.

- Destination: /usr/libexec/soc-agent-ebpf, root:root directory 0755.
- New Manifest: `2bcd28ef47e2ce75539117d72f7e1eed9d6b4408a2ca8026a00df3bd86815452`.
- New Bundle: `6849fb2ee55d75a0e1f783e902d3d878f1d030820f52eb75969ba5953e9e5914`.
- New installer SHA256: `1bd8eb15f03813e8ed1003b012afd74f9aed1d0f35652511efbb01b1aab2cde2`.
- Exact update command code SHA256: `3f7352108f1eeec4aa83cd3525b160c081df0827de35155036ab1c3cc5b40278`.

| File | Mode | SHA256 |
| --- | --- | --- |
| bootstrap | 0555 | `96d0df57066e3f1004a4343d22acbe6c0ca20aef7d6919181e8ca2010dcbbd7d` |
| broker | 0555 | `b872565bcd0abc67c2a5b9c7f96b21d9acb46df582870e303e067c42376254ff` |
| entry | 0555 | `8e4ef82c3fe45ae5a414509316a2922898148ed860bb7ebdde9f743509ce4455` |
| libnative-tc.so | 0444 | `7905693372d14e93162ff7fbeea4068a0094a737663b2403c337630901706536` |
| manifest.bin | 0444 | `3b2b75a30acf69b8546356cacc9b45748fdfb8df6b6bc8f8507b055b08b3bdba` |
| pam-policy.conf | 0444 | `93af76067bf513b4db8c5a9bd606e348ccde334b83e52f7dc71544c9c1f82696` |
| tc.bpf.o | 0444 | `928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a` |
| release.json | 0444 | `2bcd28ef47e2ce75539117d72f7e1eed9d6b4408a2ca8026a00df3bd86815452` |
| release.trust | 0444 | `9c5570e9401b0621fbb676ec6715643735a1e2a3c58334d89aca1326e2733508` |

## Exact update and failure contract

The shell-free command is stored in
`.git/tcx-c2-execution/v043-update-command-awaiting-approval.json`.
It uses the reviewed /usr/bin/sudo -k → /usr/bin/env -i PATH=/usr/bin:/bin LANG=C →
/usr/bin/python3 -I -S -c boundary. Its fixed code reads both old/new installers
using O_NOFOLLOW held FDs, checks regular single-link files and the exact separately
pinned SHA256 values BEFORE executing either image. It imports no project Python
as Root and accepts no caller-selected command, object or Root executable path.

First, the existing exact-manifest rollback engine verifies ownership, file set,
SHA/modes and process quiescence, then atomically moves only Release 0.4.2 to:
`/usr/libexec/.soc-agent-ebpf.rollback-17f85c891df7f5b04026fcf180b6c175fece64752ceb2f2793dd36917e0c910d`.
It deletes no file and does not touch any Hook. Existing destination/archive/staging
conflicts or unknown contents fail closed. Next the new pinned installer publishes
only the exact nine files using atomic no-replace rename. No existing file is
overwritten. The old release is retained for recovery.

If publication fails after unpublishing, stop with the old archive retained and
no B/C or automatic retry; manual restoration needs a verified recovery plan.
No PAM/NSS/sudoers policy, service, setuid bit, file capability, qdisc, filter,
model, raw data, audit history or prior Native session is edited by this update.
No long-lived Root process or Native collector starts during installation.

After update approval, reverify all installed files/owner/mode/dependencies and
Manifest. Start a fresh B session: confirm the displayed scope with yes, then
enter the OS password. Stop and verify B before C. C remains lo/Ingress/current
namespace, 300 seconds, 4096 events, queue 32, 256 MiB address space, 20 CPU seconds,
no traffic generation/drop/payload retention/pinning/foreign link changes/retry.
A failure stops progression and requires renewed authorization for a new attempt.
Native AI, DNS9 and operational promotion remain BLOCKED. Kernel TCX support,
capability transfer, authentication, packet delivery and Link cleanup remain PENDING.
