"""Observed packet metadata, diagnostic flows and permanently closed producer gates."""

from typing import Literal

from pydantic import Field, IPvAnyAddress, model_validator

from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp


class CaptureConfig(Snapshot):
    version: Literal["soc-linux-capture:v1"] = "soc-linux-capture:v1"
    interface: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,15}$")
    idle_seconds: float = Field(default=30, ge=1, le=300, allow_inf_nan=False)
    active_seconds: float = Field(default=120, ge=1, le=3600, allow_inf_nan=False)
    max_flows: int = Field(default=128, strict=True, ge=1, le=1024)
    retain_query_names: bool = False
    packet_batch: int = Field(default=16, strict=True, ge=1, le=64)
    origin: Literal["NATIVE_AF_PACKET", "EXPLICIT_PACKET_FIXTURE"] = "NATIVE_AF_PACKET"


class DNSObservation(Snapshot):
    transaction_id: int = Field(ge=0, le=65535)
    response: bool
    response_code: int = Field(ge=0, le=15)
    query_type: int = Field(ge=0, le=65535)
    query_class: int = Field(ge=0, le=65535)
    query_name: str | None = Field(default=None, max_length=255)
    query_name_digest: Hash
    name_representation: Literal["UNCOMPRESSED_WIRE_LABELS_CASE_PRESERVED"] = (
        "UNCOMPRESSED_WIRE_LABELS_CASE_PRESERVED"
    )


class PacketObservation(Snapshot):
    version: Literal["soc-packet-metadata:v1"] = "soc-packet-metadata:v1"
    interface_id: Hash
    source_address: IPvAnyAddress
    destination_address: IPvAnyAddress
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    transport: Literal["tcp", "udp"]
    ip_version: Literal[4, 6]
    direction: Literal["INBOUND", "OUTBOUND", "UNKNOWN"]
    timestamp: UTCTimestamp
    timestamp_origin: Literal["KERNEL_SO_TIMESTAMPNS", "FIXTURE"]
    capture_timestamp_ns: int | None = Field(default=None, strict=True, ge=0, le=2**63 - 1)
    frame_length: int = Field(ge=1, le=65535)
    ip_length: int = Field(ge=20, le=65535)
    tcp_flags: int = Field(default=0, ge=0, le=511)
    tcp_window: int | None = Field(default=None, ge=0, le=65535)
    header_length: int = Field(ge=8, le=512)
    raw_frame_digest: Hash
    dns: DNSObservation | None = None
    dns_status: str = Field(default="NOT_DNS", max_length=64)

    @model_validator(mode="after")
    def capture_binding(self):
        if (
            self.source_address.version != self.ip_version
            or self.destination_address.version != self.ip_version
        ):
            raise ValueError("PACKET_ADDRESS_FAMILY_MISMATCH")
        if self.header_length > self.ip_length or self.ip_length + 14 > self.frame_length:
            raise ValueError("PACKET_LENGTH_BINDING_MISMATCH")
        if self.transport == "udp" and (self.tcp_flags or self.tcp_window is not None):
            raise ValueError("UDP_CANNOT_HAVE_TCP_OBSERVATIONS")
        if self.dns is not None and (
            53 not in (self.source_port, self.destination_port) or self.dns_status != "DNS_PARSED"
        ):
            raise ValueError("DNS_TRANSPORT_BINDING_MISMATCH")
        native = self.timestamp_origin == "KERNEL_SO_TIMESTAMPNS"
        if native != (self.capture_timestamp_ns is not None):
            raise ValueError("PACKET_CAPTURE_CLOCK_MISMATCH")
        if native:
            from datetime import UTC, datetime

            seconds, nanos = divmod(self.capture_timestamp_ns, 10**9)
            expected = datetime.fromtimestamp(seconds, UTC).replace(microsecond=nanos // 1000)
            if self.timestamp != expected:
                raise ValueError("PACKET_CAPTURE_TIME_MISMATCH")
        return self


class DNSNativeEvent(Snapshot):
    version: Literal["soc-native-dns-diagnostic:v1"] = "soc-native-dns-diagnostic:v1"
    event_id: Hash
    source_event_id: str
    source: SourceIdentity
    timestamp: UTCTimestamp
    source_address: IPvAnyAddress
    destination_address: IPvAnyAddress
    source_port: int
    destination_port: int
    transport: Literal["tcp", "udp"]
    question: DNSObservation
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class FlowSummary(Snapshot):
    version: Literal["soc-diagnostic-flow:v1"] = "soc-diagnostic-flow:v1"
    flow_id: Hash
    interface_id: Hash
    source_address: IPvAnyAddress
    destination_address: IPvAnyAddress
    source_port: int
    destination_port: int
    transport: Literal["tcp", "udp"]
    started_at: UTCTimestamp
    ended_at: UTCTimestamp
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    frame_length_min: int
    frame_length_max: int
    frame_length_mean: float
    tcp_flag_counts: tuple[tuple[str, int], ...]
    duration_seconds: float
    close_reason: Literal[
        "IDLE_TIMEOUT", "ACTIVE_TIMEOUT", "SHUTDOWN", "RESTART_GAP", "PACKET_LIMIT"
    ]
    incomplete: Literal[True] = True
    direction_definition: Literal["FIRST_OBSERVED_NOT_TRAINING_PRODUCER"] = (
        "FIRST_OBSERVED_NOT_TRAINING_PRODUCER"
    )
    feature_status: Literal["DIAGNOSTIC_ONLY"] = "DIAGNOSTIC_ONLY"
    source_event_ids: tuple[str, ...] = Field(min_length=1, max_length=4096)


def model_gates() -> dict[str, dict[str, str]]:
    # No caller-set verified bit: no original producer revision/config/Golden Pair exists.
    return {
        name: {
            "operational_input": "NOT_INFERABLE",
            "inference": "BLOCKED",
            "finding_promotion": "BLOCKED",
            "feature_generation": "DIAGNOSTIC_ONLY",
            "reason": "ORIGINAL_PRODUCER_REVISION_CONFIG_AND_GOLDEN_PAIR_MISSING",
        }
        for name in ("network-quality", "network-edge", "dns")
    }
