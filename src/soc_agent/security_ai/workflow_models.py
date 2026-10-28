"""Offline composition contracts. Advisory classification never grants response authority."""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, IPvAnyAddress, JsonValue, TypeAdapter, model_validator

from soc_agent.review.models import Hash
from soc_agent.security_ai.features import SecurityRecord
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.operational.source_records import DNSQuerySource
from soc_agent.security_ai.research.models import Frozen
from soc_agent.state.evidence import UTCTimestamp


class ReplayJob(Frozen):
    kind: Literal["network14_replay"]
    flow_index: int = Field(ge=0, le=3, strict=True)
    profiles: tuple[Literal["quality", "edge"], ...] = ("quality", "edge")


class PacketWindowJob(Frozen):
    kind: Literal["packet_window"]
    origin: Literal["OFFLINE_PCAP", "FIXTURE"]
    session: UUID
    source_sha256: Hash
    clock_epoch: str = Field(min_length=1, max_length=128)
    quality: Literal["ELIGIBLE", "INCOMPLETE", "INVALID", "UNKNOWN"]
    close_reason: str = Field(min_length=1, max_length=64)
    packets: tuple[PacketObservation, ...] = Field(min_length=1, max_length=128)
    identities: tuple[UUID, ...] = Field(min_length=1, max_length=128)
    witness_ns: int = Field(ge=0)
    profiles: tuple[Literal["quality", "edge"], ...] = ("quality", "edge")


class DNSFixtureJob(Frozen):
    kind: Literal["dns_fixture"]
    fixture_index: int = Field(ge=0, le=1, strict=True)


class StoredDNSJob(Frozen):
    kind: Literal["stored_dns"]
    sources: tuple[DNSQuerySource, ...] = Field(min_length=1, max_length=4096)


class DNSWireMessage(Frozen):
    transport: Literal["udp", "tcp"]
    timestamp_ns: int = Field(ge=0, le=2**63 - 1, strict=True)
    source_address: IPvAnyAddress
    destination_address: IPvAnyAddress
    source_port: int = Field(ge=0, le=65535, strict=True)
    destination_port: int = Field(ge=0, le=65535, strict=True)
    source_reference: Hash
    wire_hex: str = Field(min_length=2, max_length=8196, pattern=r"^(?:[0-9a-f]{2})+$")

    @model_validator(mode="after")
    def dns_scope(self):
        if 53 not in (self.source_port, self.destination_port):
            raise ValueError("RAW_DNS_PORT_SCOPE")
        if self.source_address.version != self.destination_address.version:
            raise ValueError("RAW_DNS_ADDRESS_FAMILY_MISMATCH")
        return self


class RawDNSJob(Frozen):
    kind: Literal["raw_dns"]
    origin: Literal["FIXTURE", "DECLARED_PCAP_TRANSCRIPT"]
    source_sha256: Hash
    clock_epoch: str = Field(min_length=1, max_length=200)
    messages: tuple[DNSWireMessage, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def unique_sources(self):
        if len({m.source_reference for m in self.messages}) != len(self.messages):
            raise ValueError("RAW_DNS_DUPLICATE_SOURCE_REFERENCE")
        return self


class PackageInput(Frozen):
    directory: str = Field(min_length=1, max_length=4096)
    manifest_sha256: Hash


class RecordsJob(Frozen):
    kind: Literal["stored_records"]
    origin: Literal["FIXTURE", "DECLARED_STORED_RECORDS"]
    records: tuple[SecurityRecord, ...] = Field(min_length=1, max_length=4096)
    packages: tuple[PackageInput, ...] = Field(min_length=1, max_length=3)


class NativeCheckpointJob(Frozen):
    kind: Literal["native_checkpoint"]
    summary: dict[str, JsonValue]
    transport: dict[str, JsonValue]


class TCXAnalysisJob(Frozen):
    kind: Literal["tcx_analysis"]
    origin: Literal["REAL_NATIVE", "FIXTURE"]
    session: UUID
    namespace: str = Field(pattern=r"^net:\[[1-9][0-9]*\]$")
    release_manifest: Hash
    result: dict[str, JsonValue]
    profiles: tuple[Literal["quality", "edge"], ...] = Field(
        default=("quality", "edge"), min_length=1, max_length=2
    )

    @model_validator(mode="after")
    def unique_profiles(self):
        if len(set(self.profiles)) != len(self.profiles):
            raise ValueError("TCX_DUPLICATE_MODEL_PROFILE")
        return self


class CollectorFailureJob(Frozen):
    kind: Literal["collector_error"]
    code: str = Field(min_length=1, max_length=128)
    # Caller-reported failure, not an authenticated Native collector error.
    record: SecurityRecord | None = None


Job = Annotated[
    ReplayJob
    | PacketWindowJob
    | DNSFixtureJob
    | StoredDNSJob
    | RawDNSJob
    | RecordsJob
    | NativeCheckpointJob
    | TCXAnalysisJob
    | CollectorFailureJob,
    Field(discriminator="kind"),
]
JOB = TypeAdapter(Job)


def submitted_job(submitted: dict) -> Job:
    """Normalize pinned Supervisor bytes only with explicit retained expected Scope."""
    if submitted.get("tcx_scope") is not None:
        import json

        from soc_agent.security_ai.tcx_input import from_supervisor

        return from_supervisor(json.loads(submitted["utf8"]), **submitted["tcx_scope"])
    return JOB.validate_json(submitted["utf8"])


Classification = Literal[
    "NORMAL",
    "KNOWN_THREAT",
    "UNKNOWN_ANOMALY",
    "DATA_QUALITY_FAILURE",
    "COLLECTOR_ERROR",
    "MODEL_ERROR",
]


class EvidenceEnvelope(Frozen):
    event_identity: str
    domain: Literal["NETWORK", "DNS", "AUTHENTICATION", "COLLECTOR"]
    origin: str
    source_digest: Hash
    collector_identity: str
    observed_at: UTCTimestamp | None
    source_incident: UUID | None = None
    schema_version: str
    session: str | None = None
    release: str | None = None
    namespace: str | None = None
    interface: str | None = None
    integrity: Literal["REPLAY_VERIFIED", "FIXTURE", "DECLARED_UNATTESTED", "UNVERIFIED"]
    provenance: tuple[str, ...]


class InferenceRecord(Frozen):
    event_identity: str
    model_id: str
    model_version: str
    model_manifest_digest: Hash
    artifact_digest: Hash
    feature_fingerprint: Hash
    evidence_references: tuple[str, ...] = Field(min_length=1)
    prediction: str
    score: float | None = None
    score_semantics: str
    inferred_at: UTCTimestamp
    latency_ms: float = Field(ge=0)
    status: Literal["SUCCESS"] = "SUCCESS"
    # Retain original result/receipt instead of converting it into an observation.
    receipt: dict[str, JsonValue]


class AnalysisOutcome(Frozen):
    contract: Literal["soc-offline-analysis-outcome:v1"] = "soc-offline-analysis-outcome:v1"
    incident_id: UUID
    classification: Classification
    classification_basis: Literal["ADVISORY_NOT_CONFIRMED_INCIDENT"] = (
        "ADVISORY_NOT_CONFIRMED_INCIDENT"
    )
    eligibility: Literal["ELIGIBLE", "INCOMPLETE", "INVALID", "UNKNOWN"]
    eligibility_scope: Literal["OFFLINE_ONLY_NO_NATIVE_ADMISSION"] = (
        "OFFLINE_ONLY_NO_NATIVE_ADMISSION"
    )
    evidence: tuple[EvidenceEnvelope, ...]
    inference: tuple[InferenceRecord, ...]
    reasons: tuple[str, ...]
    fusion: dict[str, JsonValue] | None = None
    investigation: dict[str, JsonValue] | None = None
    response: dict[str, JsonValue] | None = None
    llm_mode: Literal["SCRIPTED", "INJECTED_CLIENT", "REAL_API"]
    external_provider_calls: int | None = Field(default=None, ge=0)
    action_policy: Literal["READ_ONLY_EXISTING_POLICY"] = "READ_ONLY_EXISTING_POLICY"
    native_execution: Literal[False] = False
    uncertainty: Literal["UNKNOWN"] = "UNKNOWN"
    limitations: tuple[str, ...] = (
        "No cross-domain actor attribution or averaged/calibrated risk from model scores",
        "Research/fixture model success is not Native or production approval",
        "Read-only postconditions do not establish host or collector remediation",
    )
