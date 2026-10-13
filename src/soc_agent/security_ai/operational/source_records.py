"""Declared operational observations; no source attestation or inference authority."""

from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.realtime.models import SourceIdentity
from soc_agent.security_ai.authentication.aggregation import AuthenticationEvent
from soc_agent.security_ai.external.models import Snapshot, Text, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp


class SourceHeader(Snapshot):
    incident_id: UUID
    event_id: Text
    source: SourceIdentity
    collector_id: Text
    collector_version: Text
    observed_at: UTCTimestamp
    source_assurance: Literal["DECLARED_UNATTESTED"] = "DECLARED_UNATTESTED"


class AuthenticationSource(Snapshot):
    contract_version: Literal["soc-operational-auth-source:v1"] = "soc-operational-auth-source:v1"
    kind: Literal["authentication"] = "authentication"
    header: SourceHeader
    event: AuthenticationEvent

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (
            self.event.event_id != self.header.event_id
            or self.event.event_time != self.header.observed_at
        ):
            raise ValueError("Authentication source identity/time mismatch")
        if any(
            len(v) > 128
            for v in (self.event.event_id, self.event.account_id, self.event.source_identifier)
        ):
            raise ValueError("Authentication reference exceeds boundary")
        return self

    @property
    def content_digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class FlowEndpoint(Snapshot):
    address: str
    port: int | None = Field(default=None, strict=True, ge=0, le=65535)

    @model_validator(mode="after")
    def address_valid(self) -> Self:
        from ipaddress import ip_address

        try:
            ip_address(self.address)
        except ValueError:
            raise ValueError("Invalid declared endpoint address") from None
        return self


class NetworkFlowSource(Snapshot):
    contract_version: Literal["soc-operational-network-source:v1"] = (
        "soc-operational-network-source:v1"
    )
    kind: Literal["network"] = "network"
    header: SourceHeader
    transport: Literal["tcp", "udp", "icmp"]
    endpoint_a: FlowEndpoint
    endpoint_b: FlowEndpoint
    started_at: UTCTimestamp
    ended_at: UTCTimestamp
    reported_packet_count: int | None = Field(default=None, strict=True, ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def ordered(self) -> Self:
        from ipaddress import ip_address

        if self.started_at > self.ended_at or self.header.observed_at != self.ended_at:
            raise ValueError("Flow source interval mismatch")
        if (
            ip_address(self.endpoint_a.address).version
            != ip_address(self.endpoint_b.address).version
        ):
            raise ValueError("Flow address families differ")
        ports = (self.endpoint_a.port, self.endpoint_b.port)
        if self.transport in ("tcp", "udp") and any(p is None for p in ports):
            raise ValueError("Observed transport ports required")
        if self.transport == "icmp" and any(p is not None for p in ports):
            raise ValueError("ICMP does not carry transport ports")
        return self

    @property
    def content_digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class DNSQuerySource(Snapshot):
    contract_version: Literal["soc-operational-dns-source:v1"] = "soc-operational-dns-source:v1"
    kind: Literal["dns"] = "dns"
    header: SourceHeader
    query_name: str = Field(min_length=1, max_length=255)
    query_type: int = Field(strict=True, ge=1, le=65535)
    query_class: int = Field(strict=True, ge=1, le=65535)
    transaction_id: int = Field(strict=True, ge=0, le=65535)
    name_policy: Literal["PRESERVE_TEXT_NO_IDNA_TRANSFORM"] = "PRESERVE_TEXT_NO_IDNA_TRANSFORM"

    @model_validator(mode="after")
    def bounded_name(self) -> Self:
        if len(self.query_name.encode("utf-8")) > 1024 or any(
            c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.query_name
        ):
            raise ValueError("Invalid declared DNS query text")
        return self

    @property
    def content_digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


OperationalSource = Annotated[
    AuthenticationSource | NetworkFlowSource | DNSQuerySource, Field(discriminator="kind")
]
