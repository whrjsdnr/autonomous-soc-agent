"""Bounded end-of-stream accounting, independent of Native capture quality."""

from pathlib import Path
from typing import Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from soc_agent.security_ai.research.models import Frozen


class CounterSnapshot(Frozen):
    packet_records: int = Field(ge=0, le=4096, strict=True)
    supported_packet_records: int = Field(ge=0, le=4096, strict=True)
    unsupported_packet_records: int = Field(ge=0, le=4096, strict=True)
    network_events: int = Field(ge=0, le=8190, strict=True)
    dns_events: int = Field(ge=0, le=8190, strict=True)
    pkts_recvd: int = Field(ge=0, strict=True)
    pkts_dropped: int = Field(ge=0, strict=True)
    pkts_link: int = Field(ge=0, strict=True)
    bytes_recvd: int = Field(ge=0, strict=True)

    def verify(self, packets: int, unsupported: int, network: int, dns: int):
        if (
            self.packet_records,
            self.supported_packet_records,
            self.unsupported_packet_records,
            self.network_events,
            self.dns_events,
        ) != (packets, packets - unsupported, unsupported, network, dns):
            raise ValueError("ZEEK_COUNTER_ACCOUNTING_MISMATCH")

    def verify_closed(self, closed):
        if any(getattr(closed, key) != value for key, value in self.model_dump().items()):
            raise ValueError("ZEEK_CLOSED_COUNTER_MISMATCH")


class Closed(Frozen):
    stop_reason: Literal[
        "ZEEK_DONE", "PACKET_LIMIT_REACHED", "EVENT_LIMIT_REACHED", "OUTPUT_LIMIT_REACHED"
    ]
    packet_records: int = Field(ge=0, le=4096, strict=True)
    supported_packet_records: int | None = Field(default=None, ge=0, le=4096, strict=True)
    unsupported_packet_records: int | None = Field(default=None, ge=0, le=4096, strict=True)
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

    @model_serializer(mode="wrap")
    def serialize_counts(self, handler: SerializerFunctionWrapHandler) -> dict:
        value = handler(self)
        for name in ("supported_packet_records", "unsupported_packet_records"):
            if value.get(name) is None:
                value.pop(name, None)
        return value

    @model_validator(mode="after")
    def split_counts(self):
        if (self.supported_packet_records is None) != (self.unsupported_packet_records is None):
            raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
        if self.supported_packet_records is not None and (
            self.supported_packet_records + self.unsupported_packet_records != self.packet_records
        ):
            raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
        return self

    def verify(
        self,
        *,
        sequence: int,
        packets: int,
        network: int,
        dns: int,
        unsupported: int = 0,
        counter_messages: int = 0,
    ):
        if (
            sequence != self.messages_before_closed + 1
            or self.messages_before_closed != 1 + packets + network + dns + counter_messages
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
        if self.supported_packet_records is not None:
            if (
                self.supported_packet_records,
                self.unsupported_packet_records,
                counter_messages,
            ) != (packets - unsupported, unsupported, 1):
                raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
        elif unsupported or counter_messages:
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
        self.unsupported = 0
        self.counter_snapshot: CounterSnapshot | None = None
        self.total_received = self.invalid = self.duplicate = self.sequence_gap = 0

    def diagnostics(self) -> dict:
        return dict(
            total_received=self.total_received,
            packet_observations=self.packets,
            supported_packet=self.packets - self.unsupported,
            unsupported_packet=self.unsupported,
            network_event=self.network,
            dns_event=self.dns,
            invalid_record=self.invalid,
            duplicate=self.duplicate,
            sequence_gap=self.sequence_gap,
            counter_snapshot=self.counter_snapshot.model_dump() if self.counter_snapshot else None,
            closed=self.closed is not None,
        )

    def accept(self, envelope, line: bytes):
        self.total_received += 1
        self.duplicate += int(envelope.sequence <= self.sequence)
        self.sequence_gap += int(envelope.sequence > self.sequence + 1)
        try:
            self._accept(envelope, line)
        except (ValueError, TypeError):
            self.invalid += 1
            raise

    def _accept(self, envelope, line: bytes):
        if self.closed or envelope.sequence != self.sequence + 1:
            raise ValueError("ZEEK_STREAM_SEQUENCE_INTEGRITY")
        if envelope.kind == "ready":
            if self.sequence or envelope.data:
                raise ValueError("ZEEK_STREAM_READY_INVALID")
        elif not self.sequence:
            raise ValueError("ZEEK_STREAM_READY_MISSING")
        elif self.counter_snapshot is not None and envelope.kind != "closed":
            raise ValueError("ZEEK_STREAM_POST_COUNTER_RECORD")
        elif envelope.kind in {"packet", "unsupported"}:
            from soc_agent.security_ai.collectors.packet_metadata import packet_metadata

            packet_metadata(envelope.kind, envelope.data)
            if envelope.data.get("sequence") != self.packets + 1 or self.packets >= 4096:
                raise ValueError("ZEEK_STREAM_PACKET_INTEGRITY")
            self.packets += 1
            self.unsupported += int(envelope.kind == "unsupported")
        elif envelope.kind == "network":
            self.network += 1
        elif envelope.kind == "dns":
            self.dns += 1
        elif envelope.kind == "counter":
            counter = CounterSnapshot.model_validate(envelope.data)
            counter.verify(self.packets, self.unsupported, self.network, self.dns)
            self.counter_snapshot = counter
        elif envelope.kind == "closed":
            from soc_agent.security_ai.collectors.dns_visibility import closed_data

            body, _ = closed_data(envelope.data)
            proof = Closed.model_validate(body)
            proof.verify(
                sequence=envelope.sequence,
                packets=self.packets,
                network=self.network,
                dns=self.dns,
                unsupported=self.unsupported,
                counter_messages=int(self.counter_snapshot is not None),
            )
            if proof.bytes_before_closed != self.bytes:
                raise ValueError("ZEEK_CLOSED_ACCOUNTING_MISMATCH")
            if self.counter_snapshot:
                self.counter_snapshot.verify_closed(proof)
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
