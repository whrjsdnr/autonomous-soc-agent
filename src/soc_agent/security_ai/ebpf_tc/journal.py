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
TCX_OWNER = struct.Struct("<QQQIIIIII8s16s32s")
TCX_ROW = struct.Struct("<32s32s104sII32s32s")
TCX_KINDS = {
    "TCX_ATTACH_REQUESTED",
    "TCX_LINK_CREATED",
    "TCX_LINK_VERIFIED",
    "TCX_DETACH_REQUESTED",
    "TCX_LINK_RELEASED",
    "TCX_CLEANUP_VERIFIED",
    "TCX_CLEANUP_UNVERIFIED",
}
assert TCX_OWNER.size == 104 and TCX_ROW.size == 240
RC_ROW = struct.Struct("<32s32s80sII32s32s")
assert RC_ROW.size == 216
assert ROW.size == 192


def recover_native(path: Path, approval: str) -> dict:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 240 * 1024:
        os.close(fd)
        raise ValueError("NATIVE_JOURNAL_BOUND")
    previous, ordinal, claimed_cleanup = bytes(32), 0, False
    release_manifest_digest = None
    last_owner = None
    mutation_observed = False
    with os.fdopen(fd, "rb") as stream:
        while header := stream.read(64):
            if ordinal >= 1024:
                raise ValueError("NATIVE_JOURNAL_BOUND")
            if len(header) != 64:
                raise ValueError("NATIVE_JOURNAL_PARTIAL")
            kind = header[32:].split(b"\0", 1)[0].decode("ascii")
            layout = (
                RC_ROW
                if kind == "RC_RELEASE_VERIFIED"
                else TCX_ROW
                if kind.startswith("TCX_")
                else ROW
            )
            body = header + stream.read(layout.size - 64)
            if len(body) != layout.size:
                raise ValueError("NATIVE_JOURNAL_PARTIAL")
            plan, raw_kind, owner, sequence, count, before, checksum = layout.unpack(body)
            if (
                plan.hex() != approval
                or count != ordinal + 1
                or before != previous
                or hashlib.sha256(body[:-32]).digest() != checksum
                or kind not in KINDS | TCX_KINDS | {"RC_RELEASE_VERIFIED"}
                or sequence > 2048
            ):
                raise ValueError("NATIVE_JOURNAL_INTEGRITY")
            if kind == "RC_RELEASE_VERIFIED":
                version = owner[32:48].split(b"\0", 1)[0]
                import re

                if (
                    not any(owner[:32])
                    or not re.fullmatch(rb"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", version)
                    or release_manifest_digest is not None
                ):
                    raise ValueError("NATIVE_RELEASE_JOURNAL_INTEGRITY")
                release_manifest_digest = owner[:32].hex()
            previous, ordinal = checksum, count
            if kind in {"ATTACH_REQUESTED", "TCX_ATTACH_REQUESTED", "TCX_LINK_CREATED"}:
                mutation_observed = True
            if kind == "TCX_LINK_VERIFIED":
                last_owner = TCX_OWNER.unpack(owner)
            if kind == "ATTACH_VERIFIED":
                last_owner = OWNER.unpack(owner)
            if kind in {"CLEANUP_VERIFIED", "TCX_CLEANUP_VERIFIED"}:
                claimed_cleanup = True
            if kind in {
                "ATTACH_REQUESTED",
                "CLEANUP_UNVERIFIED",
                "TCX_ATTACH_REQUESTED",
                "TCX_LINK_CREATED",
                "TCX_CLEANUP_UNVERIFIED",
            }:
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
        release_manifest_digest=release_manifest_digest,
        records=ordinal,
        claimed_cleanup=claimed_cleanup,
        last_owner_observed=last_owner is not None,
        state="ORPHANED"
        if (last_owner is not None or mutation_observed) and not claimed_cleanup
        else "RECOVERY_REQUIRES_USER_REVIEW",
        process_exit="UNKNOWN",
        authentication_restored=False,
        automatic_attach=False,
        automatic_inference=False,
        native_ai="BLOCKED",
    )
