"""Versioned monitoring contracts; findings are advisory, never execution authority."""

from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.state.evidence import UTCTimestamp


class RuntimeConfig(Snapshot):
    version: Literal["soc-linux-monitor:v1"] = "soc-linux-monitor:v1"
    incident_id: UUID
    # Required operator-supplied thresholds: no demo threshold is auto-adopted.
    repeated_failures: int = Field(strict=True, ge=2, le=10000)
    multiple_accounts: int = Field(strict=True, ge=2, le=10000)
    threshold_assurance: Literal["OPERATOR_SUPPLIED_UNVALIDATED"] = "OPERATOR_SUPPLIED_UNVALIDATED"
    poll_seconds: float = Field(default=2, ge=0.2, le=300, allow_inf_nan=False)
    batch_size: int = Field(default=16, strict=True, ge=1, le=16)
    worker_batch: int = Field(default=32, strict=True, ge=1, le=256)
    pending_limit: int = Field(default=128, strict=True, ge=1, le=1024)
    collector_retry_limit: int = Field(default=3, strict=True, ge=0, le=10)
    investigation_retry_limit: int = Field(default=0, strict=True, ge=0, le=3)
    investigation_seconds: float = Field(default=120, ge=1, le=300, allow_inf_nan=False)
    shutdown_seconds: float = Field(default=5, ge=0.1, le=30, allow_inf_nan=False)
    max_llm_calls: int = Field(default=2, strict=True, ge=2, le=2)
    max_tool_calls: int = Field(default=2, strict=True, ge=1, le=8)
    circuit_failures: int = Field(default=3, strict=True, ge=1, le=10)
    assessment_mode: Literal["READ_ONLY", "REAL_LLM"] = "READ_ONLY"
    env_file: Path | None = Field(default=None, repr=False)

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))


class Finding(Snapshot):
    version: Literal["soc-linux-finding:v1"] = "soc-linux-finding:v1"
    finding_id: Hash
    incident_id: UUID
    rule_id: str
    severity: Literal["info", "low"]
    event_references: tuple[str, ...] = Field(min_length=1)
    evidence_references: tuple[Hash, ...] = Field(min_length=1)
    first_seen: UTCTimestamp
    last_seen: UTCTimestamp
    detection_reason: str
    provenance: tuple[Hash, ...] = Field(min_length=1)
    input_origin: Literal["NATIVE_OS", "FIXTURE"]
    processing_status: Literal["PENDING"] = "PENDING"
    meaning: Literal["DETERMINISTIC_ADVISORY_NOT_ATTACK_FACT"] = (
        "DETERMINISTIC_ADVISORY_NOT_ATTACK_FACT"
    )

    @property
    def digest(self) -> str:
        return content_digest_payload(self.model_dump(mode="json"))
