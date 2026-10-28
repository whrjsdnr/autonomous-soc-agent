"""Packet metadata bridge to Network14; no capture, privilege or model loading."""

from typing import Literal, Self, TypedDict
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.research.models import Frozen, digest

FEATURE_CONTRACT = "84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e"
PRODUCER_CONFIG = "7999723911ce3d2e9cd3b3b6e0d45e11f44b1316cdf9c7f4883d7e2a69ca21a7"
TIMEOUT_CLOSURES = frozenset({"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"})


class FlowEligibilityCounts(TypedDict):
    eligible: int | None
    rejected: int | None
    pending: int | None
    by_close_reason: dict[str, int]


def lifecycle_eligible(close_reason: str) -> bool:
    """Timeout candidacy only; never substitutes for source/counter/finalization gates."""
    return close_reason in TIMEOUT_CLOSURES


class LiveRequest(Frozen):
    contract: Literal["soc-live-network-input:v1"] = "soc-live-network-input:v1"
    research_mode: Literal[True]
    origin: Literal["NATIVE_AF_PACKET", "FIXTURE", "OFFLINE_PCAP"]
    profile: Literal["quality", "edge"]
    invocation_id: UUID
    capture_session: UUID
    flow_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    provenance_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    packet_event_ids: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    packets: tuple[PacketObservation, ...] = Field(min_length=1, max_length=128)
    capture_quality: Literal["UNKNOWN"] = "UNKNOWN"
    feature_contract_digest: Literal[FEATURE_CONTRACT] = FEATURE_CONTRACT
    producer_configuration_digest: Literal[PRODUCER_CONFIG] = PRODUCER_CONFIG

    @model_validator(mode="after")
    def metadata_binding(self) -> Self:
        if len(self.packets) != len(self.packet_event_ids) or len(
            set(self.packet_event_ids)
        ) != len(self.packets):
            raise ValueError("LIVE_DUPLICATE_OR_MISSING_PACKET_REFERENCE")
        first = self.packets[0]
        pair = {
            (str(first.source_address), first.source_port),
            (str(first.destination_address), first.destination_port),
        }
        for packet in self.packets:
            if (
                packet.interface_id != first.interface_id
                or packet.transport != first.transport
                or {
                    (str(packet.source_address), packet.source_port),
                    (str(packet.destination_address), packet.destination_port),
                }
                != pair
                or packet.timestamp_origin
                != ("KERNEL_SO_TIMESTAMPNS" if self.origin == "NATIVE_AF_PACKET" else "FIXTURE")
                or packet.dns is not None
            ):
                raise ValueError("LIVE_PACKET_SOURCE_MISMATCH")
        times = [timestamp_ns(p) for p in self.packets]
        if times[-1] - times[0] >= 120_000_000_000 or any(
            not 0 <= b - a < 30_000_000_000 for a, b in zip(times, times[1:], strict=False)
        ):
            raise ValueError("LIVE_ORDER_OR_PRODUCER_TIMEOUT")
        return self


def timestamp_ns(packet: PacketObservation) -> int:
    if packet.capture_timestamp_ns is not None:
        return packet.capture_timestamp_ns
    from datetime import UTC, datetime

    delta = packet.timestamp - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000


def producer_packets(request: LiveRequest):
    # Imported only by the isolated native worker or explicit producer tests.
    from ml.verified_producers.network import Packet

    return tuple(Packet(**p) for p in packet_metadata(request))


def packet_metadata(request: LiveRequest) -> list[dict]:
    return [
        dict(
            event_id=str(identity),
            interface_id=p.interface_id,
            capture_session_id=str(request.capture_session),
            timestamp_ns=timestamp_ns(p),
            source_address=str(p.source_address),
            destination_address=str(p.destination_address),
            source_port=p.source_port,
            destination_port=p.destination_port,
            transport=p.transport,
            ip_length=p.ip_length,
            tcp_flags=p.tcp_flags,
        )
        for identity, p in zip(request.packet_event_ids, request.packets, strict=True)
    ]


def expected_source(request: LiveRequest) -> str:
    return digest(
        dict(
            packets=packet_metadata(request),
            source_identity=source_binding(request),
            origin=request.origin,
            quality="UNKNOWN",
        )
    )


def validate_result(request: LiveRequest, receipt) -> None:
    import struct

    feature_hash = digest(
        dict(
            producer_id="linux-observable-network",
            version="1.1.0",
            configuration_digest=PRODUCER_CONFIG,
            source_digest=receipt.source_digest,
            feature_names=receipt.feature_names,
            dtype="float32",
            values=receipt.feature_values,
            source_origin=request.origin,
            quality="UNKNOWN",
        )
    )
    if (
        receipt.request_digest != digest(request.model_dump(mode="json"))
        or receipt.invocation_id != request.invocation_id
        or receipt.profile != request.profile
        or receipt.origin != request.origin
        or receipt.capture_session != request.capture_session
        or receipt.flow_id != request.flow_id
        or receipt.provenance_digest != request.provenance_digest
        or receipt.source_digest != expected_source(request)
        or receipt.feature_digest != feature_hash
        or receipt.packet_count != len(request.packets)
        or receipt.event_time != request.packets[0].timestamp
        or any(struct.unpack("!f", struct.pack("!f", n))[0] != n for n in receipt.feature_values)
    ):
        raise ValueError("LIVE_RECEIPT_INPUT_BINDING_MISMATCH")


def parity_check() -> None:
    """Fixed hand-calculated arithmetic reference across origins, never model inference.

    40/60/80 IP bytes, forward/reverse/forward, times 1/1.5/2 seconds,
    flags SYN/ACK/FIN. Population variance = (400+0+400)/3.
    Physical NIC/offload/capture completeness is outside this check.
    """
    import struct

    from ml.verified_producers.network import Packet
    from ml.verified_producers.network_v1_1 import network_features

    packets = tuple(
        Packet(
            str(i),
            "a" * 64,
            "parity-reference",
            ns,
            "127.0.0.1",
            "127.0.0.2",
            1000,
            2000,
            "tcp",
            length,
            flags,
        )
        if i != 1
        else Packet(
            str(i),
            "a" * 64,
            "parity-reference",
            ns,
            "127.0.0.2",
            "127.0.0.1",
            2000,
            1000,
            "tcp",
            length,
            flags,
        )
        for i, (ns, length, flags) in enumerate(
            [(1_000_000_000, 40, 2), (1_500_000_000, 60, 16), (2_000_000_000, 80, 1)]
        )
    )
    expected = tuple(
        struct.unpack("!f", struct.pack("!f", n))[0]
        for n in (1, 2, 1, 120, 60, 40, 80, 60, (800 / 3) ** 0.5, 1, 1, 0, 0.5, 0.5)
    )
    for origin in ("OFFLINE_PCAP", "NATIVE_AF_PACKET", "FIXTURE"):
        vector = network_features(packets, source_origin=origin, source_identity="b" * 64)
        if vector.values != expected or vector.configuration_digest != PRODUCER_CONFIG:
            raise ValueError("LIVE_METADATA_PARITY_REFERENCE_FAILED")


def produce(request: LiveRequest):
    from ml.verified_producers.contracts import digest as ml_digest
    from ml.verified_producers.network_v1_1 import (
        feature_contract,
        network_features,
        producer_contract,
    )

    if (
        ml_digest(feature_contract()) != FEATURE_CONTRACT
        or ml_digest(producer_contract()) != PRODUCER_CONFIG
    ):
        raise ValueError("LIVE_PRODUCER_CONTRACT_MISMATCH")
    return network_features(
        producer_packets(request),
        source_origin=request.origin,
        source_identity=source_binding(request),
        capture_quality="UNKNOWN",
    )


def source_binding(request: LiveRequest) -> str:
    return digest(request.model_dump(mode="json", exclude={"invocation_id", "profile"}))
