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
    fd_release_evidence = []
    data_send_status = []
    data_counter_status = []
    data_counter_queries = []
    data_socket_samples = []
    data_delivery_failed = False
    last_link_lifecycle = None
    with os.fdopen(fd, "rb") as stream:
        while header := stream.read(64):
            if ordinal >= 1024:
                raise ValueError("NATIVE_JOURNAL_BOUND")
            if len(header) != 64:
                raise ValueError("NATIVE_JOURNAL_PARTIAL")
            kind = header[32:].split(b"\0", 1)[0].decode("ascii")
            layout = (
                RC_ROW
                if kind
                in {
                    "RC_RELEASE_VERIFIED",
                    "LOADER_DIAGNOSTIC",
                    "LOADER_VERIFIER_LOG",
                    "FD_RELEASE_EVIDENCE",
                    "DATA_SEND_STATUS",
                    "DATA_COUNTER_STATUS",
                    "DATA_COUNTER_QUERY",
                    "DATA_SOCKET_SAMPLE",
                    "FIXTURE_COUNTER_STATUS",
                }
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
                | {
                    "RC_RELEASE_VERIFIED",
                    "LOADER_DIAGNOSTIC",
                    "LOADER_VERIFIER_LOG",
                    "FD_RELEASE_EVIDENCE",
                    "DATA_SEND_STATUS",
                    "DATA_COUNTER_STATUS",
                    "DATA_COUNTER_QUERY",
                    "DATA_SOCKET_SAMPLE",
                    "FIXTURE_COUNTER_STATUS",
                }
                or sequence > 2048
            ):
                raise ValueError("NATIVE_JOURNAL_INTEGRITY")
            if kind in TCX_KINDS:
                last_link_lifecycle = kind
            if kind == "DATA_SOCKET_SAMPLE":
                version, message, phase, seq, result, saved, queued, capacity, stamp, waited = (
                    struct.unpack("<10q", owner)
                )
                if (
                    version != 1
                    or message not in {1, 2, 3, 4, 5}
                    or phase not in {1, 2, 3}
                    or not 0 <= seq <= 65568
                    or not 0 <= saved <= 4095
                    or stamp <= 0
                    or waited < 0
                    or len(data_socket_samples) >= 64
                ):
                    raise ValueError("DATA_SOCKET_SAMPLE_SCHEMA")
                data_socket_samples.append(
                    dict(
                        message=message,
                        phase=phase,
                        sequence=seq,
                        outq_result=result,
                        outq_errno=saved or None,
                        queued_bytes=queued if result == 0 else None,
                        send_buffer_bytes=capacity if capacity > 0 else None,
                        send_buffer_errno=-capacity if capacity < 0 else None,
                        timestamp_ns=stamp,
                        cumulative_wait_ns=waited,
                    )
                )
            if kind == "DATA_COUNTER_QUERY":
                version, drain, cpus, fd, lookup, saved, sent, elapsed, generation, source = (
                    # Keep signed syscall results, but preserve all generation bits.
                    # Same 80-byte layout/digest as historical two's-complement rows.
                    struct.unpack("<8qQq", owner)
                )
                if (
                    version != 1
                    or not 0 <= saved <= 4095
                    or elapsed < 0
                    or source not in {1, 2, 5, 6, 13, 14}
                    or not 0 < generation < 2**64
                    or len(data_counter_queries) >= 16
                ):
                    raise ValueError("DATA_COUNTER_QUERY_SCHEMA")
                data_counter_queries.append(
                    dict(
                        source="FIXTURE" if source & 3 == 2 else "OWNED_MAP_NATIVE_JOURNAL",
                        drain_result=drain,
                        possible_cpus_result=cpus,
                        map_fd_result=fd,
                        lookup_result=lookup,
                        saved_errno=saved or None,
                        transmit_result=sent,
                        elapsed_ns=elapsed,
                        generation=generation,
                        lookup_attempted=bool(source & 4),
                        sum_overflow=bool(source & 8),
                    )
                )
            if kind in {"DATA_COUNTER_STATUS", "FIXTURE_COUNTER_STATUS"}:
                generation, stamp, *values = struct.unpack("<QQ7QII", owner)
                totals, status, delivered = values[:7], values[7], values[8]
                if (
                    not generation
                    or not stamp
                    or status not in {1, 2}
                    or delivered > 4096
                    or len(data_counter_status) >= 16
                    or status == 2
                    and any(totals)
                ):
                    raise ValueError("DATA_COUNTER_STATUS_SCHEMA")
                data_counter_status.append(
                    dict(
                        source="FIXTURE_COUNTER_NEVER_NATIVE"
                        if kind.startswith("FIXTURE")
                        else "OWNED_MAP_JOURNAL_CLAIM_NOT_RUNTIME_ATTESTATION",
                        generation=generation,
                        timestamp_ns=stamp,
                        delivered=delivered,
                        retrieval="SUCCESS" if status == 1 else "UNVERIFIED",
                        totals=dict(
                            zip(
                                (
                                    "observed",
                                    "emitted",
                                    "ring_lost",
                                    "unsupported",
                                    "malformed",
                                    "disabled",
                                    "budget",
                                ),
                                totals,
                                strict=True,
                            )
                        )
                        if status == 1
                        else None,
                        scope="COUNTER_OBSERVATION_NOT_PROOF_OF_SOCKET_DELIVERY",
                    )
                )
            if kind == "DATA_SEND_STATUS":
                fields = struct.unpack("<4I5Qq4I", owner)
                version, message, status, stopping = fields[:4]
                seq, calls, waited, last_sent, packets, result, saved, size, waits, retries = (
                    fields[4:]
                )
                if (
                    version != 1
                    or message not in {1, 2, 3, 4, 5}
                    or status not in {1, 2, 3, 4}
                    or stopping not in {0, 1}
                    or size != 192
                    or waits > 40
                    or retries > waits
                    or last_sent > seq
                    or seq > 65568
                    or len(data_send_status) >= 16
                ):
                    raise ValueError("DATA_SEND_STATUS_SCHEMA")
                data_delivery_failed |= status in {2, 4} or status == 3 and result != 0
                data_send_status.append(
                    dict(
                        message=("READY", "PACKET", "CLOSED", "RUN_END", "COUNTER")[message - 1],
                        status={
                            1: "BACKPRESSURE_OBSERVED",
                            2: "FAILED",
                            3: "FINAL",
                            4: "POLL_FAILED",
                        }[status],
                        stopping=bool(stopping),
                        sequence=seq,
                        send_calls=calls,
                        waited_ns=waited,
                        last_delivered_sequence=last_sent,
                        packets_sent=packets,
                        result=result,
                        saved_errno=saved,
                        requested_bytes=size,
                        readiness_waits=waits,
                        resumed_sends=retries,
                        api="poll" if status == 4 else "send" if status in {1, 2} else "data_close",
                    )
                )
            if kind == "FD_RELEASE_EVIDENCE":
                detail = decode_diagnostic(owner)
                if (
                    detail["api"] != "object_fd_closed_check"
                    or detail["stage"] != "CLEANUP"
                    or not detail["fd_inventory_available"]
                    or not detail["owned_object_released"]
                    or len(fd_release_evidence) >= 16
                ):
                    raise ValueError("FD_RELEASE_EVIDENCE_SCHEMA")
                fd_release_evidence.append(
                    dict(
                        map_fds_checked=detail["map_fds_observed"],
                        program_fds_checked=detail["program_fds_observed"],
                        all_observed_fds_closed=detail["return_value"] == 0,
                        result=detail["return_value"],
                        method="LIBBPF_CLOSE_THEN_F_GETFD_EBADF_SINGLE_THREADED",
                        raw_close_returnvalues_observed=False,
                    )
                )
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
    claimed_cleanup = claimed_cleanup and not data_delivery_failed
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
        data_send_status=data_send_status,
        data_counter_status=data_counter_status,
        data_counter_queries=data_counter_queries,
        data_socket_samples=data_socket_samples,
        fd_release_evidence=fd_release_evidence,
        last_link_lifecycle=last_link_lifecycle,
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
