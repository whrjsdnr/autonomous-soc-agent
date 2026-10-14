"""Actual monitor outcomes; never fabricated core WorkflowCheckpoint/StateAnchor records."""

import json
from typing import Literal, Self
from uuid import UUID

from pydantic import model_validator

from soc_agent.investigation import InvestigationResult
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload


class RuntimeExperience(Snapshot):
    contract_version: Literal["soc-monitor-experience:v1"] = "soc-monitor-experience:v1"
    experience_id: Hash
    incident_id: UUID
    finding_id: Hash
    finding_digest: Hash
    investigation_id: UUID
    investigation_digest: Hash
    result_digest: Hash
    evidence_references: tuple[Hash, ...]
    provenance_references: tuple[Hash, ...]
    source_digest: Hash
    source_origin: Literal["NATIVE_OS", "FIXTURE"]
    assessment_mode: Literal["READ_ONLY", "SCRIPTED", "REAL_LLM"]
    authority: Literal["NONE"] = "NONE"

    @model_validator(mode="after")
    def integrity(self) -> Self:
        if self.experience_id != content_digest_payload(
            self.model_dump(mode="json", exclude={"experience_id"})
        ):
            raise ValueError("RUNTIME_EXPERIENCE_DIGEST_REJECTED")
        return self


def capture_runtime_experience(monitor, finding_id: str) -> RuntimeExperience:
    monitor.store.verify_audit()
    with monitor.store.database.transaction(write=False) as c:
        finding, result_digest, source_digest = monitor.simulation._context(c, finding_id)
        row = c.execute("SELECT result FROM monitor_findings WHERE id=?", (finding_id,)).fetchone()
    result = json.loads(row["result"])
    investigation = InvestigationResult.model_validate(result["investigation"])
    body = {
        "contract_version": "soc-monitor-experience:v1",
        "incident_id": str(finding.incident_id),
        "finding_id": finding_id,
        "finding_digest": finding.digest,
        "investigation_id": str(investigation.plan.plan_id),
        "investigation_digest": result["investigation_digest"],
        "result_digest": result_digest,
        "evidence_references": list(finding.evidence_references),
        "provenance_references": list(finding.provenance),
        "source_digest": source_digest,
        "source_origin": finding.input_origin,
        "assessment_mode": result.get("mode", "READ_ONLY"),
        "authority": "NONE",
    }
    return RuntimeExperience.model_validate_json(
        json.dumps(body | {"experience_id": content_digest_payload(body)})
    )
