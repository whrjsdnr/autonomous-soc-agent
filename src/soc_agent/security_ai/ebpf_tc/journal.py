"""Read-only Native journal decoder. A hash chain is not Native attestation by itself."""

import hashlib
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
    if path.is_symlink() or not 0 < path.stat().st_size <= 192 * 1024:
        raise ValueError("NATIVE_JOURNAL_BOUND")
    previous, ordinal, claimed_cleanup = bytes(32), 0, False
    last_owner = None
    with path.open("rb") as stream:
        while body := stream.read(ROW.size):
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
    return dict(
        source="NATIVE_JOURNAL_CLAIM_NOT_RUNTIME_ATTESTATION",
        audit_digest=previous.hex(),
        records=ordinal,
        claimed_cleanup=claimed_cleanup,
        last_owner_observed=last_owner is not None,
        state="RECOVERY_REQUIRES_USER_REVIEW",
        process_exit="UNKNOWN",
        authentication_restored=False,
        automatic_attach=False,
        automatic_inference=False,
        native_ai="BLOCKED",
    )
