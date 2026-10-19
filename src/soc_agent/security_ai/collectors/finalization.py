"""Bounded end-of-stream accounting, independent of Native capture quality."""

from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.research.models import Frozen


class Closed(Frozen):
    stop_reason: Literal[
        "ZEEK_DONE", "PACKET_LIMIT_REACHED", "EVENT_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED"
    ]
    packet_records: int = Field(ge=0, le=4096, strict=True)
    network_events: int = Field(ge=0, le=8190, strict=True)
    dns_events: int = Field(ge=0, le=8190, strict=True)
    messages_before_closed: int = Field(ge=1, le=8191, strict=True)
    bytes_before_closed: int = Field(ge=0, le=8386560, strict=True)
    omitted_packet_records: int = Field(ge=0, strict=True)
    omitted_events: int = Field(ge=0, strict=True)
    pkts_recvd: int = Field(ge=0, strict=True)
    pkts_dropped: int = Field(ge=0, strict=True)
    pkts_link: int = Field(ge=0, strict=True)
    bytes_recvd: int = Field(ge=0, strict=True)

    def verify(self, *, sequence: int, packets: int, network: int, dns: int):
        if (
            sequence != self.messages_before_closed + 1
            or self.messages_before_closed != 1 + packets + network + dns
            or (packets, network, dns)
            != (self.packet_records, self.network_events, self.dns_events)
            or (self.stop_reason == "PACKET_LIMIT_REACHED" and packets != 4096)
            or (self.stop_reason == "EVENT_LIMIT_REACHED" and sequence != 8192)
            or (
                self.stop_reason == "ZEEK_DONE"
                and (self.omitted_events or self.omitted_packet_records)
            )
        ):
            raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
        if self.pkts_dropped:
            raise ValueError("ZEEK_CAPTURE_DROPS_DETECTED")


def termination_reason(closed: Closed, exit_code: int, requested: str | None) -> str:
    """Keep the Zeek hook's actual reason; classify external signals separately."""
    if exit_code not in {0, 124}:
        raise ValueError("ZEEK_CONTAINER_EXIT_UNVERIFIED")
    if closed.stop_reason != "ZEEK_DONE":
        return closed.stop_reason
    if requested:
        return requested
    if exit_code == 124:
        return "SESSION_TIMEOUT"
    return "INPUT_EXHAUSTED"  # Only the offline fixture path may claim this.


class Ledger:
    """Launcher-side counts over exact bytes, before any host persistence."""

    def __init__(self):
        self.sequence = self.packets = self.network = self.dns = self.bytes = 0
        self.closed: Closed | None = None

    def accept(self, envelope, line: bytes):
        if self.closed or envelope.sequence != self.sequence + 1:
            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
        if envelope.kind == "ready":
            if self.sequence or envelope.data:
                raise ValueError("ZEEK_STREAM_READY_INVALID")
        elif not self.sequence:
            raise ValueError("ZEEK_STREAM_READY_MISSING")
        elif envelope.kind == "packet":
            if envelope.data.get("sequence") != self.packets + 1 or self.packets >= 4096:
                raise ValueError("ZEEK_STREAM_PACKET_INTEGRITY")
            self.packets += 1
        elif envelope.kind == "network":
            self.network += 1
        elif envelope.kind == "dns":
            self.dns += 1
        elif envelope.kind == "closed":
            proof = Closed.model_validate(envelope.data)
            proof.verify(
                sequence=envelope.sequence, packets=self.packets, network=self.network, dns=self.dns
            )
            if proof.bytes_before_closed != self.bytes:
                raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
            self.closed = proof
        if envelope.sequence > 8192 or self.bytes + len(line) > 8388608:
            raise ValueError("ZEEK_STREAM_OUTPUT_BUDGET")
        self.sequence = envelope.sequence
        self.bytes += len(line)


def publish(path: Path, value: dict) -> None:
    """Publish a complete private certificate atomically, without replacing evidence."""
    import json
    import os
    from uuid import uuid4

    from soc_agent.review.persistence.secure_storage import validate_directory

    validate_directory(path.parent)
    body = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    if len(body) > 8192:
        raise ValueError("ZEEK_CERTIFICATE_SIZE_LIMIT")
    temporary = path.with_name(".publish-" + uuid4().hex)
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        # link is an atomic no-replace publish; rename/replace could overwrite evidence.
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
