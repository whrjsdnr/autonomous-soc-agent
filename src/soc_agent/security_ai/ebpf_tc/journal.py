"""Read-only Native journal decoder. A hash chain is not Native attestation by itself."""

import hashlib
import os
import stat
import struct
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.contracts import OWNER

ROW = struct.Struct("<32s32s56sII32s32s")
KINDS = {
    "AUTHENTICATION_VERIFIED",
    "BROKER_READY",
    "LOAD_REQUESTED",
    "LOAD_VERIFIED",
    "ATTACH_REQUESTED",
    "ATTACH_VERIFIED",
    "DETACH_REQUESTED",
    "DETACH_VERIFIED",
    "CLEANUP_VERIFIED",
    "CLEANUP_UNVERIFIED",
    "BROKER_EXITED",
}
assert ROW.size == 192


def recover_native(path: Path, approval: str) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 192 * 1024:
        os.close(fd)
        raise ValueError("NATIVE_JOURNAL_BOUND")
    previous, ordinal, claimed_cleanup = bytes(32), 0, False
    last_owner = None
    with os.fdopen(fd, "rb") as stream:
        while body := stream.read(ROW.size):
            if ordinal >= 1024:
                raise ValueError("NATIVE_JOURNAL_BOUND")
            if len(body) != ROW.size:
                raise ValueError("NATIVE_JOURNAL_PARTIAL")
            plan, raw_kind, owner, sequence, count, before, checksum = ROW.unpack(body)
            kind = raw_kind.split(b"\0", 1)[0].decode("ascii")
            if (
                plan.hex() != approval
                or count != ordinal + 1
                or before != previous
                or hashlib.sha256(body[:-32]).digest() != checksum
                or kind not in KINDS
            ):
                raise ValueError("NATIVE_JOURNAL_INTEGRITY")
            previous, ordinal = checksum, count
            if kind == "ATTACH_VERIFIED":
                last_owner = OWNER.unpack(owner)
            if kind == "CLEANUP_VERIFIED":
                claimed_cleanup = True
            if kind in {"ATTACH_REQUESTED", "CLEANUP_UNVERIFIED"}:
                claimed_cleanup = False
        after = os.fstat(stream.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("NATIVE_JOURNAL_CHANGED")
    return dict(
        source="NATIVE_JOURNAL_CLAIM_NOT_RUNTIME_ATTESTATION",
        audit_digest=previous.hex(),
        records=ordinal,
        claimed_cleanup=claimed_cleanup,
        last_owner_observed=last_owner is not None,
        state="ORPHANED"
        if last_owner is not None and not claimed_cleanup
        else "RECOVERY_REQUIRES_USER_REVIEW",
        process_exit="UNKNOWN",
        authentication_restored=False,
        automatic_attach=False,
        automatic_inference=False,
        native_ai="BLOCKED",
    )
