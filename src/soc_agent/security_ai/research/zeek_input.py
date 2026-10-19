"""Zeek offline provenance stays distinct from Native and generic fixture receipts."""

from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.collectors.packet_input import SCOPE, Packet, metadata
from soc_agent.security_ai.collectors.packet_producer import Window
from soc_agent.security_ai.research.live_input import FEATURE_CONTRACT, PRODUCER_CONFIG
from soc_agent.security_ai.research.models import Frozen, digest


class ZeekRequest(Frozen):
    contract: Literal["soc-zeek-network14-input:v1"] = "soc-zeek-network14-input:v1"
    research_mode: Literal[True]
    origin: Literal["ZEEK_OFFLINE_PCAP"] = "ZEEK_OFFLINE_PCAP"
    profile: Literal["quality", "edge"]
    invocation_id: UUID
    capture_session: UUID
    flow_id: Hash
    provenance_digest: Hash
    pcap_sha256: Hash
    packet_log_sha256: Hash
    script_sha256: Hash
    close_reason: Literal["IDLE_TIMEOUT", "ACTIVE_TIMEOUT"]
    scope: Literal[SCOPE] = SCOPE
    packets: tuple[Packet, ...] = Field(min_length=1, max_length=128)
    feature_values: tuple[float, ...] = Field(min_length=14, max_length=14)

    @model_validator(mode="after")
    def arithmetic(self) -> Self:
        w = Window()
        first = self.packets[0]
        previous = 0
        for p in self.packets:
            if p.key != first.key or p.sequence <= previous or (p.kind == "udp" and p.tcp_flags):
                raise ValueError("ZEEK_REQUEST_FLOW_IDENTITY")
            if (p.source, p.source_port) == (p.destination, p.destination_port):
                raise ValueError("ZEEK_REQUEST_AMBIGUOUS_DIRECTION")
            if w.packets and (
                p.ns - first.ns >= 120_000_000_000 or p.ns - w.packets[-1].ns >= 30_000_000_000
            ):
                raise ValueError("ZEEK_REQUEST_TIMEOUT_BOUNDARY")
            w.add(p)
            previous = p.sequence
        calculated = w.finish(self.close_reason, str(self.capture_session))
        if (
            tuple(calculated["values"]) != self.feature_values
            or calculated["flow_id"] != self.flow_id
        ):
            raise ValueError("ZEEK_REQUEST_FEATURE_OR_FLOW_MISMATCH")
        return self


def source_binding(request: ZeekRequest) -> str:
    return digest(request.model_dump(mode="json", exclude={"invocation_id", "profile"}))


def expected_source(request: ZeekRequest) -> str:
    return digest(
        dict(
            packets=metadata(request.packets, str(request.capture_session), request.pcap_sha256),
            source_identity=source_binding(request),
            origin="OFFLINE_PCAP",
            quality="UNKNOWN",
        )
    )


def produce(request: ZeekRequest):
    from ml.verified_producers.contracts import digest as ml_digest
    from ml.verified_producers.network import Packet as MLPacket
    from ml.verified_producers.network_v1_1 import (
        feature_contract,
        network_features,
        producer_contract,
    )

    if (
        ml_digest(feature_contract()) != FEATURE_CONTRACT
        or ml_digest(producer_contract()) != PRODUCER_CONFIG
    ):
        raise ValueError("ZEEK_REFERENCE_PRODUCER_CONTRACT_CHANGED")
    vector = network_features(
        tuple(
            MLPacket(**p)
            for p in metadata(request.packets, str(request.capture_session), request.pcap_sha256)
        ),
        source_origin="OFFLINE_PCAP",
        source_identity=source_binding(request),
        capture_quality="UNKNOWN",
    )
    if vector.values != request.feature_values or vector.source_digest != expected_source(request):
        raise ValueError("ZEEK_NETWORK14_REFERENCE_PARITY_FAILED")
    return vector


def validate_result(request: ZeekRequest, receipt):
    if (
        receipt.contract != "soc-zeek-network14-receipt:v1"
        or receipt.origin != request.origin
        or receipt.request_digest != digest(request.model_dump(mode="json"))
        or receipt.invocation_id != request.invocation_id
        or receipt.profile != request.profile
        or receipt.capture_session != request.capture_session
        or receipt.flow_id != request.flow_id
        or receipt.provenance_digest != request.provenance_digest
        or receipt.source_digest != expected_source(request)
        or receipt.pcap_sha256 != request.pcap_sha256
        or receipt.packet_log_sha256 != request.packet_log_sha256
        or receipt.script_sha256 != request.script_sha256
        or receipt.feature_values != request.feature_values
        or receipt.packet_count != len(request.packets)
        or receipt.event_time != request.packets[0].timestamp
    ):
        raise ValueError("ZEEK_RECEIPT_PROVENANCE_MISMATCH")
    expected = digest(
        dict(
            producer_id="linux-observable-network",
            version="1.1.0",
            configuration_digest=PRODUCER_CONFIG,
            source_digest=receipt.source_digest,
            feature_names=receipt.feature_names,
            dtype="float32",
            values=receipt.feature_values,
            source_origin="OFFLINE_PCAP",
            quality="UNKNOWN",
        )
    )
    if receipt.feature_digest != expected:
        raise ValueError("ZEEK_RECEIPT_FEATURE_DIGEST_MISMATCH")
