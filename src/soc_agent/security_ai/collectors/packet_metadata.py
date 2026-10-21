"""Live observation types: unsupported metadata is evidence, never a feature packet."""

from typing import Literal

from pydantic import Field, IPvAnyAddress, model_validator

from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import FlowAssembly
from soc_agent.security_ai.research.models import Frozen

EVENT_TYPES = {
    "ready": "SESSION_READY",
    "packet": "SUPPORTED_PACKET",  # Preserve the existing supported wire spelling.
    "unsupported": "UNSUPPORTED_PACKET",
    "network": "NETWORK_EVENT",
    "dns": "DNS_EVENT",
    "counter": "COUNTER",
    "closed": "CLOSED",
}


class UnsupportedPacket(Frozen):
    sequence: int = Field(gt=0, le=4096, strict=True)
    seconds: int = Field(ge=0, lt=2**32, strict=True)
    microseconds: int = Field(ge=0, lt=1000000, strict=True)
    # Original pcap wire/captured lengths are uint32, not an IP uint16 length.
    # This broader diagnostic domain does NOT widen the canonical Packet model.
    frame_length: int = Field(ge=0, lt=2**32, strict=True)
    captured_length: int = Field(ge=0, lt=2**32, strict=True)
    kind: Literal["UNSUPPORTED", "tcp", "udp"]
    source: IPvAnyAddress | None = None
    destination: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    destination_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    ip_length: int | None = Field(default=None, ge=0, lt=2**32, strict=True)
    tcp_flags: int | None = Field(default=None, ge=0, le=255, strict=True)

    @model_validator(mode="after")
    def coherent(self):
        if self.captured_length > self.frame_length:
            raise ValueError("ZEEK_UNSUPPORTED_LENGTH_INVALID")
        ip = (self.source, self.destination, self.ip_length)
        transport = (self.source_port, self.destination_port, self.tcp_flags)
        if any(v is not None for v in ip) and any(v is None for v in ip):
            raise ValueError("ZEEK_UNSUPPORTED_PARTIAL_IDENTITY")
        if any(v is not None for v in transport) and (
            any(v is None for v in transport) or any(v is None for v in ip)
        ):
            raise ValueError("ZEEK_UNSUPPORTED_PARTIAL_IDENTITY")
        if self.kind in {"tcp", "udp"}:
            if any(v is None for v in ip + transport):
                raise ValueError("ZEEK_UNSUPPORTED_PARTIAL_IDENTITY")
            if (
                self.frame_length == self.captured_length
                and self.frame_length <= 65535
                and self.ip_length <= 65535
                and self.ip_length + 14 <= self.frame_length
            ):
                raise ValueError("ZEEK_UNSUPPORTED_CLASSIFICATION_MISMATCH")
        return self


def packet_metadata(kind: str, data: dict) -> Packet | UnsupportedPacket:
    """Never infer a canonical packet from legacy/malformed unsupported data."""
    if kind == "unsupported":
        return UnsupportedPacket.model_validate(data)
    if kind == "packet":
        return Packet.model_validate(data)
    raise ValueError("ZEEK_PACKET_EVENT_KIND_INVALID")


class ObservationFlows(FlowAssembly):
    """Zeek-only sequence cursor; excluded observations add no window/feature data.

    Keep original observation numbers on later supported packets. The unchanged
    TCX assembler uses its existing contiguous delivery contract.
    """

    def exclude(self, metadata: UnsupportedPacket) -> None:
        if self.closed or metadata.sequence != self.count + 1 or self.count >= 4096:
            raise ValueError("ZEEK_FLOW_SEQUENCE_INTEGRITY")
        self.count += 1
