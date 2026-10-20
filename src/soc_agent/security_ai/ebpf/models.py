"""Independent TC provenance. Kernel monotonic time is never relabelled as UTC."""

from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, IPvAnyAddress, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen, digest


class Plan(Frozen):
    collector: Literal["EBPF_TC", "EBPF_TCX"] = "EBPF_TC"
    contract: Literal["soc-ebpf-tc-plan:v1"] = "soc-ebpf-tc-plan:v1"
    session_id: UUID = Field(default_factory=uuid4)
    generation: int = Field(gt=0, lt=2**64, strict=True)
    program_sha256: Hash
    source_digest: Hash
    interface: Literal["lo"] = "lo"
    ifindex: int = Field(gt=0, lt=2**32, strict=True)
    net_namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    hook: Literal["INGRESS", "EGRESS"]
    origin: Literal["EBPF_TC_NATIVE", "EBPF_TC_FIXTURE", "TCX_STREAM_FIXTURE"]
    clock: Literal["KERNEL_MONOTONIC_NS", "FIXTURE_PCAP_EVENT_NS"]
    event_limit: Literal[4096] = 4096
    queue_capacity: Literal[32] = 32
    duration_seconds: Literal[300] = 300
    ring_bytes: Literal[262144] = 262144
    native_ai: Literal["BLOCKED"] = "BLOCKED"

    @model_validator(mode="after")
    def clock_scope(self):
        if (self.origin in {"EBPF_TC_NATIVE", "TCX_STREAM_FIXTURE"}) != (
            self.clock == "KERNEL_MONOTONIC_NS"
        ):
            raise ValueError("EBPF_CLOCK_ORIGIN_MISMATCH")
        return self

    @property
    def identity(self) -> str:
        return digest(self.model_dump(mode="json"))


class Event(Frozen):
    collector: Literal["EBPF_TC", "EBPF_TCX"] = "EBPF_TC"
    session_id: UUID
    program_sha256: Hash
    plan_digest: Hash
    generation: int = Field(gt=0, lt=2**64, strict=True)
    ifindex: int = Field(gt=0, lt=2**32, strict=True)
    net_namespace: str = Field(pattern=r"^net:\[[0-9]+\]$")
    hook: Literal["INGRESS", "EGRESS"]
    delivery_sequence: int = Field(ge=1, le=4096, strict=True)
    cpu: int = Field(ge=0, le=8191, strict=True)
    cpu_sequence: int = Field(gt=0, lt=2**64, strict=True)
    timestamp_ns: int = Field(ge=0, lt=2**63, strict=True)
    clock: Literal["KERNEL_MONOTONIC_NS", "FIXTURE_PCAP_EVENT_NS"]
    source: IPvAnyAddress
    destination: IPvAnyAddress
    source_port: int = Field(ge=0, le=65535, strict=True)
    destination_port: int = Field(ge=0, le=65535, strict=True)
    protocol: Literal["tcp", "udp"]
    frame_length: int = Field(ge=42, le=65535, strict=True)
    ip_length: int = Field(ge=28, le=65535, strict=True)
    tcp_flags: int = Field(ge=0, le=255, strict=True)
    integrity: Literal["UNVERIFIED"] = "UNVERIFIED"
    counter_provenance: Literal["TC_HOOK_CPU_CUMULATIVE_GENERATION"] = (
        "TC_HOOK_CPU_CUMULATIVE_GENERATION"
    )

    @model_validator(mode="after")
    def lengths(self):
        minimum = (40 if self.source.version == 6 else 20) + (20 if self.protocol == "tcp" else 8)
        if (
            self.source.version != self.destination.version
            or not minimum <= self.ip_length <= self.frame_length - 14
            or self.protocol == "udp"
            and self.tcp_flags
        ):
            raise ValueError("EBPF_UNSUPPORTED_METADATA")
        return self

    @property
    def ns(self) -> int:
        return self.timestamp_ns

    @property
    def sequence(self) -> int:
        return self.delivery_sequence

    @property
    def key(self) -> tuple:
        return self.protocol, tuple(
            sorted(
                (
                    (str(self.source), self.source_port),
                    (str(self.destination), self.destination_port),
                )
            )
        )

    @property
    def flow_identity(self) -> str:
        return digest(
            dict(
                session=str(self.session_id),
                hook=self.hook,
                interface=self.ifindex,
                namespace=self.net_namespace,
                protocol=self.protocol,
                endpoints=sorted(
                    (
                        (str(self.source), self.source_port),
                        (str(self.destination), self.destination_port),
                    )
                ),
            )
        )


class Counters(Frozen):
    generation: int = Field(gt=0, lt=2**64, strict=True)
    hook: Literal["INGRESS", "EGRESS"]
    cpu: int = Field(ge=0, le=8191, strict=True)
    observed: int = Field(ge=0, lt=2**64, strict=True)
    emitted: int = Field(ge=0, lt=2**64, strict=True)
    ring_lost: int = Field(ge=0, lt=2**64, strict=True)
    unsupported: int = Field(ge=0, lt=2**64, strict=True)
    malformed: int = Field(ge=0, lt=2**64, strict=True)
    disabled: int = Field(ge=0, lt=2**64, strict=True)
    budget: int = Field(ge=0, lt=2**64, strict=True)

    @model_validator(mode="after")
    def accounting(self):
        if any(v == 2**64 - 1 for k, v in self.model_dump().items() if k not in {"hook"}):
            raise ValueError("EBPF_COUNTER_SATURATED")
        if self.observed != sum(
            (
                self.emitted,
                self.ring_lost,
                self.unsupported,
                self.malformed,
                self.disabled,
                self.budget,
            )
        ):
            raise ValueError("EBPF_COUNTER_ACCOUNTING_MISMATCH")
        return self
