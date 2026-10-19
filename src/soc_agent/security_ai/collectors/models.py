"""Zeek log facts are diagnostic observations, never Network14 vectors or AI receipts."""

from typing import Literal
from uuid import UUID

from pydantic import Field, IPvAnyAddress

from soc_agent.security_ai.research.models import Frozen

Hash = str
Origin = Literal["ZEEK_OFFLINE_PCAP", "SYNTHETIC_ZEEK_JSON", "UNVERIFIED_ZEEK_LOG"]


class Source(Frozen):
    session_id: UUID
    source_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin: Origin
    version: Literal["9.0.0"] = "9.0.0"
    log_schema: Literal["zeek-conn-dns-json:v1"] = "zeek-conn-dns-json:v1"
    capture_integrity: Literal["OFFLINE_FILE_DIGEST_VERIFIED", "UNVERIFIED"] = "UNVERIFIED"


class Event(Frozen):
    contract: Literal["soc-zeek-event:v1"] = "soc-zeek-event:v1"
    event_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: Source
    kind: Literal["network", "dns"]
    uid: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    event_ns: int = Field(ge=0, le=2**63 - 1, strict=True)
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    source_port: int = Field(ge=0, le=65535, strict=True)
    destination_port: int = Field(ge=0, le=65535, strict=True)
    protocol: Literal["tcp", "udp", "icmp"]
    duration_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False, strict=True)
    forward_packets: int | None = Field(default=None, ge=0, strict=True)
    backward_packets: int | None = Field(default=None, ge=0, strict=True)
    forward_ip_bytes: int | None = Field(default=None, ge=0, strict=True)
    backward_ip_bytes: int | None = Field(default=None, ge=0, strict=True)
    missed_bytes: int | None = Field(default=None, ge=0, strict=True)
    connection_state: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,16}$")
    transaction_id: int | None = Field(default=None, ge=0, le=65535, strict=True)
    query_type: int | None = Field(default=None, ge=0, le=65535, strict=True)
    response_code: int | None = Field(default=None, ge=0, le=65535, strict=True)
    response_latency_seconds: float | None = Field(
        default=None, ge=0, allow_inf_nan=False, strict=True
    )
    ttl_seconds: tuple[float, ...] | None = Field(default=None, max_length=64)
    truncated: bool | None = Field(default=None, strict=True)
    diagnostic: Literal[
        "CONNECTION_SUMMARY",
        "MATCHED_TRANSACTION",
        "RESPONSE_WITHOUT_TIMING",
        "MISSING_RESPONSE_METADATA",
    ]
    dns_visibility: Literal[
        "PLAINTEXT_DNS_METADATA", "ENCRYPTED_DNS_VISIBILITY_LIMIT", "UNKNOWN"
    ] = "UNKNOWN"
    timestamp_provenance: Literal["ZEEK_LOG_EVENT_TIME_DECIMAL"] = "ZEEK_LOG_EVENT_TIME_DECIMAL"
    network14_parity: Literal["BLOCKED"] = "BLOCKED"
    dns9_parity: Literal["BLOCKED"] = "BLOCKED"


class CollectedEvent(Event):
    collector_sequence: int = Field(gt=0, le=4096, strict=True)
