"""Read-only Native journal decoder. A hash chain is not Native attestation by itself."""

import hashlib
import os
import stat
import struct
from pathlib import Path

from soc_agent.security_ai.ebpf_tc.contracts import OWNER
from soc_agent.security_ai.ebpf_tc.loader_diagnostics import decode_diagnostic

ROW = struct.Struct("<32s32s56sII32s32s")
KINDS = {
    "OS_AUTH_HANDOFF_VERIFIED",
    "BROKER_SESSION_BOUND",
    "BROKER_SESSION_EXPIRED",
    "BROKER_STOPPED",
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
    diagnostics = []
    verifier_log = bytearray()
    log_detail = None
    with os.fdopen(fd, "rb") as stream:
        while header := stream.read(64):
            if ordinal >= 1024:
                raise ValueError("NATIVE_JOURNAL_BOUND")
            if len(header) != 64:
                raise ValueError("NATIVE_JOURNAL_PARTIAL")
            kind = header[32:].split(b"\0", 1)[0].decode("ascii")
            layout = (
                RC_ROW
                if kind in {"RC_RELEASE_VERIFIED", "LOADER_DIAGNOSTIC", "LOADER_VERIFIER_LOG"}
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
                or kind
                not in KINDS
                | TCX_KINDS
                | {"RC_RELEASE_VERIFIED", "LOADER_DIAGNOSTIC", "LOADER_VERIFIER_LOG"}
                or sequence > 2048
            ):
                raise ValueError("NATIVE_JOURNAL_INTEGRITY")
            if kind == "LOADER_DIAGNOSTIC":
                if len(diagnostics) >= 32:
                    raise ValueError("LOADER_DIAGNOSTIC_BOUND")
                diagnostics.append(decode_diagnostic(owner))
                if diagnostics[-1]["kernel_log_bytes"]:
                    if log_detail is not None:
                        raise ValueError("NATIVE_VERIFIER_LOG_DUPLICATE")
                    log_detail = diagnostics[-1]
                claimed_cleanup = False
            if kind == "LOADER_VERIFIER_LOG":
                offset, length = struct.unpack_from("<II", owner)
                if (
                    log_detail is None
                    or offset != len(verifier_log)
                    or not 1 <= length <= 72
                    or len(verifier_log) + length > log_detail["kernel_log_bytes"]
                    or any(owner[8 + length :])
                ):
                    raise ValueError("NATIVE_VERIFIER_LOG_SCHEMA")
                verifier_log.extend(owner[8 : 8 + length])
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
    log_complete = bool(
        log_detail
        and len(verifier_log) == log_detail["kernel_log_bytes"]
        and hashlib.sha256(verifier_log).hexdigest() == log_detail["kernel_log_sha256"]
    )
    if verifier_log and len(verifier_log) == log_detail["kernel_log_bytes"] and not log_complete:
        raise ValueError("NATIVE_VERIFIER_LOG_DIGEST")
    if log_complete:
        log_detail["raw_kernel_log_retained"] = True
    return dict(
        source="NATIVE_JOURNAL_CLAIM_NOT_RUNTIME_ATTESTATION",
        loader_diagnostics=diagnostics,
        verifier_log={
            "complete": log_complete,
            "bytes_observed": len(verifier_log),
            "text": verifier_log.decode("utf-8", errors="backslashreplace")
            if log_complete
            else None,
        },
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
