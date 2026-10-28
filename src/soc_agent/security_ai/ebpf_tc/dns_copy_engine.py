"""Embedded trusted capture sidecar; globals supplied by the reviewed image.

No project imports, packet transmission, TCX, Docker, installation or shell calls.
Only analysis copies cross the inherited pipe; the controller must not log bytes.
"""

import base64
import json
import os
import select
import socket
import struct
import time
from collections.abc import Callable
from typing import Protocol


def emit_json(row: dict, deadline: float) -> None:
    body = json.dumps(row, sort_keys=True).encode() + b"\n"
    if len(body) > 4096:
        raise ValueError("DNS_COPY_MESSAGE_BOUND")
    poller = select.poll()
    poller.register(1, select.POLLOUT)
    while body:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS_COPY_PIPE_BACKPRESSURE_DEADLINE")
        if not poller.poll(max(1, min(50, int(remaining * 1000)))):
            continue
        try:
            sent = os.write(1, body)
        except BlockingIOError:
            continue
        if sent <= 0:
            raise BrokenPipeError("DNS_COPY_PIPE_CLOSED")
        body = body[sent:]


def emit_result(row: dict) -> None:
    emit_json(row, time.monotonic() + 0.5)


class CopyReceipt(Protocol):
    packet: bytes | None

    def receipt(self) -> dict: ...


def require_capture_namespace() -> None:
    # Only the SHA-held image supplies this constant; never argv/environment.
    # Historical images retain the original scope when the constant is absent.
    expected_namespace = globals().get("DNS_CAPTURE_NAMESPACE", "net:[4026531833]")
    if os.readlink("/proc/self/ns/net") != expected_namespace or socket.if_nametoindex("lo") != 1:
        raise ValueError("DNS_COPY_NAMESPACE_INTERFACE")


def capture_deadline(started: float, session_deadline: float, *, start_gate: bool) -> float:
    # The analysis worker must exit by session_deadline - 0.5. The old capture
    # endpoint (-0.75) left only 0.25s for EOF, Zeek finalization and Docker exit.
    # Reserve 0.75s for that work and keep the existing final 0.5s for cleanup.
    # Shorten observation on cold starts; never extend either outer deadline.
    deadline = min(started + 6.9, session_deadline - 1.25) if start_gate else started + 6.9
    if deadline <= started:
        raise ValueError("DNS_COPY_CAPTURE_START_DEADLINE")
    return deadline


def capture_analysis(
    uid: int,
    gid: int,
    filter_socket: Callable[[socket.socket], None],
    restrict: Callable[[], None],
    normalize: Callable[[bytes, bytes], CopyReceipt],
    receipt_chain: Callable[[str, dict], str],
    scope_digest: str,
    *,
    start_gate: bool = False,
    session_started: float | None = None,
    start_context: dict | None = None,
) -> dict:
    # Existing diagnostic socket setup/filter/drop routines are embedded verbatim.
    if os.geteuid() != 0 or uid <= 0 or gid <= 0:
        raise ValueError("DNS_COPY_ROOT_ENTRY_REQUIRED")
    require_capture_namespace()
    stage = "SOCKET_OPEN"
    try:
        session_started = time.monotonic() if session_started is None else session_started
        session_deadline = session_started + 10
        if start_gate:
            stage = "ANALYSIS_START_GATE"
            if time.monotonic() >= session_deadline - 0.75:
                raise ValueError("DNS_COPY_SESSION_DEADLINE")
            if start_context is None:
                raise ValueError("DNS_START_CONTEXT_REQUIRED")
            # Functions are embedded from the same SHA-held source, never imported as Root.
            controller_pid = start_context["controller_pid"]
            binding = start_context["binding"]
            with globals()["start_connect"](
                uid, gid, controller_pid, binding, session_deadline - 0.75
            ) as control:
                emit_result(
                    dict(
                        state="DNS_COPY_AUTHENTICATED",
                        scope_digest=scope_digest,
                        session_started=session_started,
                        deadline=session_deadline,
                        root_pid=os.getpid(),
                        binding=binding,
                    )
                )
                globals()["start_receive"](control, binding, session_deadline - 0.75)
            if time.monotonic() >= session_deadline - 0.75:
                raise ValueError("DNS_COPY_SESSION_DEADLINE")
        capture_started = time.monotonic()
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0) as channel:
            stage = "SOCKET_FILTER"
            filter_socket(channel)
            channel.setsockopt(263, 8, 1)
            channel.setsockopt(socket.SOL_SOCKET, 35, 1)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
            stage = "SOCKET_BIND"
            channel.bind(("lo", 0x0800))
            if (
                "DNS_CAPTURE_COOKIE" in globals()
                and channel.getsockopt(socket.SOL_SOCKET, 71, 8).hex()
                != globals()["DNS_CAPTURE_COOKIE"]
            ):
                raise ValueError("DNS_CAPTURE_SOCKET_NAMESPACE_COOKIE")
            stage = "PRIVILEGE_DROP"
            os.setgroups([])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            restrict()
            with open("/proc/self/status") as stream:
                caps = {
                    key: int(line.split(":", 1)[1].strip(), 16)
                    for line in stream
                    if (key := line.split(":", 1)[0]) in {"CapEff", "CapPrm", "CapInh", "CapAmb"}
                }
            if len(caps) != 4 or any(caps.values()):
                raise ValueError("DNS_COPY_CAPABILITY_LEAK")
            # Reserve socket-close scheduling time inside the seven-second cap.
            deadline = capture_deadline(capture_started, session_deadline, start_gate=start_gate)
            os.set_blocking(1, False)
            ready = dict(state="DNS_COPY_READY", capabilities=caps, scope_digest=scope_digest)
            if "DNS_CAPTURE_COOKIE" in globals():
                ready["socket_namespace_cookie"] = channel.getsockopt(
                    socket.SOL_SOCKET, 71, 8
                ).hex()
            emit_json(ready, deadline)
            received = accepted = rejected = 0
            sequence_digest = "0" * 64
            while received < 32 and (remaining := deadline - time.monotonic()) > 0:
                stage = "RECVMSG"
                channel.settimeout(remaining)
                try:
                    packet, ancillary, flags, address = channel.recvmsg(512, 256)
                except TimeoutError:
                    break
                received += 1
                aux = [body for level, kind, body in ancillary if (level, kind) == (263, 8)]
                stamps = [body for level, kind, body in ancillary if (level, kind) == (1, 35)]
                if (
                    flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or len(aux) != 1
                    or len(stamps) != 1
                    or len(stamps[0]) != 16
                ):
                    raise ValueError("DNS_COPY_TRUNCATED_OR_MISSING_METADATA")
                seconds, nanos = struct.unpack("=qq", stamps[0])
                stage = "ANALYSIS_COPY"
                copy = normalize(packet, aux[0])
                receipt = copy.receipt()
                row = dict(
                    state="DNS_COPY_PACKET",
                    sequence=received,
                    timestamp_ns=seconds * 10**9 + nanos,
                    packet_type=address[2],
                    auxiliary_hex=aux[0].hex(),
                    receipt=receipt,
                )
                sequence_digest = receipt_chain(sequence_digest, row)
                row["chain"] = sequence_digest
                if copy.packet is None:
                    rejected += 1
                else:
                    accepted += 1
                    # Transient inherited pipe only. Never write this field to audit.
                    row["analysis_frame"] = base64.b64encode(copy.packet).decode()
                stage = "PIPE_SEND"
                emit_json(row, deadline)
            stage = "SOCKET_COUNTER"
            packets, drops = struct.unpack("=II", channel.getsockopt(263, 6, 8))
        capture_closed = time.monotonic()
        return dict(
            state="CLOSED",
            received=received,
            accepted=accepted,
            rejected=rejected,
            socket_packets=packets,
            socket_drops=drops,
            final_chain=sequence_digest,
            capture_started=capture_started,
            capture_closed=capture_closed,
            capture_elapsed_seconds=capture_closed - capture_started,
            capture_integrity="ANALYSIS_COPY_PROVENANCE_ONLY_NOT_NATIVE_AI_ELIGIBILITY",
        )
    except (OSError, ValueError) as exc:
        error = dict(
            state="DNS_COPY_ERROR",
            stage=stage,
            code=type(exc).__name__,
            errno=getattr(exc, "errno", None),
            detail=str(exc),
        )
        try:
            emit_result(error)
        except (OSError, ValueError) as delivery_error:
            # Terminal-only error metadata, never a password or packet body.
            error["error_delivery_failure"] = type(delivery_error).__name__
            os.write(2, (json.dumps(error) + "\n").encode())
        raise
