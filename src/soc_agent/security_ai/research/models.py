"""Research-only contracts, separate from legacy External Context v2/provenance v3."""

import hashlib
import json
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.review.models import Hash
from soc_agent.state.evidence import UTCTimestamp

Profile = Literal["quality", "edge"]
SPECS = {
    "quality": {
        "directory": "quality_rf",
        "model_id": "linux-network14-research-v1-quality_rf",
        "sha256": "53c1029cc70b9d038bf46278818905c969dc3ddfb086c673466298ebdfa56603",
        "manifest": "80bb31b38c6e35dac1628f8c5c3ed1843ae81779ca3173a356f18473821b5f66",
        "threshold": 0.35,
    },
    "edge": {
        "directory": "edge_lr",
        "model_id": "linux-network14-research-v1-edge_lr",
        "sha256": "661322193df782f958e88eb9da23f0dc4d17be328cfa63635865ce63e0fd2882",
        "manifest": "293e6046e2b46777c383ae0b5de5951596238d4f26e552263022b9b65357e2d9",
        "threshold": 0.8,
    },
}


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class Frozen(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", allow_inf_nan=False, hide_input_in_errors=True
    )


class Request(Frozen):
    research_mode: Literal[True]
    origin: Literal["OFFLINE_PCAP"] = "OFFLINE_PCAP"
    profile: Profile
    flow_index: int = Field(ge=0, le=3, strict=True)
    invocation_id: UUID


class WorkerLimits(Frozen):
    address_space_bytes: Literal[3221225472]
    cpu_seconds: Literal[15]
    result_file_bytes: Literal[131072]
    network: Literal["DENIED"]


class Receipt(Frozen):
    contract: Literal["soc-network-research-receipt:v1"] = "soc-network-research-receipt:v1"
    status: Literal["RESEARCH_ONLY"] = "RESEARCH_ONLY"
    profile: Profile
    request_digest: Hash
    invocation_id: UUID
    model_id: str
    artifact_digest: Hash
    model_manifest_digest: Hash
    producer_version: Literal["1.1.0"] = "1.1.0"
    origin: Literal["OFFLINE_PCAP"] = "OFFLINE_PCAP"
    flow_index: int = Field(ge=0, le=3)
    flow_id: Hash
    source_sha256: Hash
    source_digest: Hash
    feature_digest: Hash
    feature_names: tuple[str, ...] = Field(min_length=14, max_length=14)
    feature_values: tuple[float, ...] = Field(min_length=14, max_length=14)
    packet_count: int = Field(ge=1, le=4096)
    event_time: UTCTimestamp
    inferred_at: UTCTimestamp
    score: float = Field(ge=0, le=1)
    threshold: float = Field(gt=0, lt=1)
    prediction: Literal["CLASS_0", "CLASS_1"]
    inference_latency_ms: float = Field(ge=0)
    worker_limits: WorkerLimits
    calibration: Literal["UNCALIBRATED_SCORE_NOT_ATTACK_PROBABILITY"] = (
        "UNCALIBRATED_SCORE_NOT_ATTACK_PROBABILITY"
    )
    uncertainty: Literal["UNKNOWN"] = "UNKNOWN"
    operational_inference: Literal["BLOCKED"] = "BLOCKED"
    write_policy: Literal["WRITE_DENIED"] = "WRITE_DENIED"

    @model_validator(mode="after")
    def exact_model(self) -> Self:
        from soc_agent.security_ai.research.environment import catalogue

        doc = catalogue()
        sample = doc["samples"][self.flow_index]
        if (
            list(self.feature_names) != doc["feature_names"]
            or digest(self.feature_values) != sample["feature_values_digest"]
            or self.flow_id != sample["flow_id"]
            or self.feature_digest != sample["feature_digest"]
            or self.source_digest != sample["source_digest"]
            or self.source_sha256 != doc["raw_sha256"]
            or self.packet_count != sample["packet_count"]
        ):
            raise ValueError("RESEARCH_FEATURE_OR_SOURCE_MISMATCH")
        spec = SPECS[self.profile]
        if (
            self.model_id != spec["model_id"]
            or self.artifact_digest != spec["sha256"]
            or self.model_manifest_digest != spec["manifest"]
            or self.threshold != spec["threshold"]
            or self.prediction != ("CLASS_1" if self.score >= self.threshold else "CLASS_0")
        ):
            raise ValueError("RESEARCH_MODEL_BINDING_MISMATCH")
        return self


class AdvisoryContext(Frozen):
    contract: Literal["soc-network-research-advisory:v1"] = "soc-network-research-advisory:v1"
    incident_id: UUID
    receipt_digest: Hash
    result: Receipt
    role: Literal["UNTRUSTED_MODEL_INFERENCE_NOT_EVIDENCE"] = (
        "UNTRUSTED_MODEL_INFERENCE_NOT_EVIDENCE"
    )
    mode: Literal["OFFLINE_RESEARCH_DEMO"] = "OFFLINE_RESEARCH_DEMO"

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if self.receipt_digest != digest(self.result.model_dump(mode="json")):
            raise ValueError("ADVISORY_RECEIPT_TAMPERED")
        return self
