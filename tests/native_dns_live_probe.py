"""Explicitly approved two-query localhost probe; default prints scope only.

Uses the existing systemd-resolved stub and its synthetic .localhost zone.
No resolver API, external address, configurable name, server, Root or retry.
Do not call execute() or pass --execute before traffic approval.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path

TARGET = ("127.0.0.53", 53)
NAMESPACE = "net:[4026531833]"
NAME = "native-0516.localhost."
QUESTION = b"\x0bnative-0516\x09localhost\x00\x00\x01\x00\x01"
PLAN = {
    "purpose": "CONTROLLED_LOCAL_DNS_TEST_NOT_GENERAL_DNS_TRAFFIC",
    "namespace": NAMESPACE,
    "target": list(TARGET),
    "qname": NAME,
    "qtype": "A",
    "queries": [
        {"transport": "UDP", "transaction_id": 0xC201},
        {"transport": "TCP", "transaction_id": 0xC202},
    ],
    "max_queries": 2,
    "timeout_seconds_each": 2,
    "max_response_bytes": 4096,
    "automatic_retry": False,
    "resolver": "EXISTING_SYSTEMD_RESOLVED_SYNTHETIC_LOCALHOST_NO_NETWORK_ROUTE",
    "native_ai": "BLOCKED",
    "dns9": "BLOCKED",
}
APPROVAL = hashlib.sha256(
    json.dumps(PLAN, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def query(transaction: int) -> bytes:
    if transaction not in {0xC201, 0xC202}:
        raise ValueError("DNS_PROBE_TRANSACTION_SCOPE")
    return struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + QUESTION


def response_header(body: bytes, transaction: int) -> dict:
    if not 12 + len(QUESTION) <= len(body) <= 4096:
        raise ValueError("DNS_PROBE_RESPONSE_SIZE")
    actual, flags, questions, answers, authority, additional = struct.unpack("!6H", body[:12])
    if (
        actual != transaction
        or not flags & 0x8000
        or questions != 1
        or body[12 : 12 + len(QUESTION)] != QUESTION
    ):
        raise ValueError("DNS_PROBE_RESPONSE_IDENTITY")
    return dict(
        transaction_id=actual,
        rcode=flags & 15,
        truncated=bool(flags & 0x200),
        answers=answers,
        authority=authority,
        additional=additional,
        bytes=len(body),
        question_matches=True,
    )


def receive_exact(channel, length: int, deadline: float) -> bytes:
    output = bytearray()
    while len(output) < length:
        channel.settimeout(max(0.001, deadline - time.monotonic()))
        if time.monotonic() >= deadline:
            raise TimeoutError("DNS_PROBE_DEADLINE")
        part = channel.recv(length - len(output))
        if not part:
            raise EOFError("DNS_PROBE_TCP_PARTIAL")
        output.extend(part)
    return bytes(output)


def execute(approval: str) -> list[dict]:
    # Check everything before constructing any socket; no DNS resolution calls.
    if approval != APPROVAL or os.readlink("/proc/self/ns/net") != NAMESPACE or os.geteuid() == 0:
        raise ValueError("DNS_PROBE_EXACT_APPROVAL_UNPRIVILEGED_NAMESPACE_REQUIRED")
    records = []
    for kind, transaction in ((socket.SOCK_DGRAM, 0xC201), (socket.SOCK_STREAM, 0xC202)):
        started = time.monotonic()
        deadline = started + 2
        with socket.socket(socket.AF_INET, kind) as channel:
            channel.settimeout(2)
            channel.bind(("127.0.0.1", 0))
            channel.connect(TARGET)  # Numeric loopback only, no getaddrinfo().
            message = query(transaction)
            sent_at = time.time_ns()
            channel.settimeout(max(0.001, deadline - time.monotonic()))
            if kind == socket.SOCK_STREAM:
                channel.sendall(struct.pack("!H", len(message)) + message)
                size = struct.unpack("!H", receive_exact(channel, 2, deadline))[0]
                if not 12 <= size <= 4096:
                    raise ValueError("DNS_PROBE_TCP_RESPONSE_BOUND")
                body = receive_exact(channel, size, deadline)
            else:
                if channel.send(message) != len(message):
                    raise OSError("DNS_PROBE_PARTIAL_DATAGRAM")
                channel.settimeout(max(0.001, deadline - time.monotonic()))
                body = channel.recv(4097)
            records.append(
                dict(
                    test_origin=PLAN["purpose"],
                    transport="TCP" if kind == socket.SOCK_STREAM else "UDP",
                    source=list(channel.getsockname()),
                    destination=list(TARGET),
                    qname=NAME,
                    qtype="A",
                    sent_at_ns=sent_at,
                    received_at_ns=time.time_ns(),
                    response=response_header(body, transaction),
                    elapsed_ns=int((time.monotonic() - started) * 1e9),
                )
            )
        # Recorded after socket context exits: local close, not inferred peer FIN.
        records[-1]["socket_closed_monotonic_ns"] = time.monotonic_ns()
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(dict(plan=PLAN, approval=APPROVAL), indent=2))
        return
    if args.receipt is None:
        parser.error("--receipt required; exclusive new private file only")
    # Reserve receipt before any traffic; a failure cannot silently retry/overwrite.
    descriptor = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        try:
            records = execute(args.approve)
        except (OSError, ValueError, EOFError) as exc:
            json.dump(
                dict(
                    plan=PLAN,
                    approval=APPROVAL,
                    state="FAILED_NO_RETRY",
                    error=type(exc).__name__,
                    errno=getattr(exc, "errno", None),
                    detail=str(exc),
                ),
                stream,
                indent=2,
            )
            stream.flush()
            os.fsync(stream.fileno())
            raise
        json.dump(
            dict(plan=PLAN, approval=APPROVAL, state="COMPLETED", records=records), stream, indent=2
        )
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == "__main__":
    main()
