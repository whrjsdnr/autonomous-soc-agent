"""Read-only, reference-only outcome projection. No labels, proposals or activation writes.

Existing offline candidate/review/promotion services remain separate explicit workflows.
A simulation review is action consent, never a false-positive or attack ground truth label.
"""

import json
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.linux_runtime.findings import validate_finding
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload


class OutcomeFeedback(Snapshot):
    feedback_id: Hash
    incident_id: UUID
    finding_reference: Hash
    finding_digest: Hash
    evidence_references: tuple[Hash, ...]
    provenance_references: tuple[Hash, ...]
    result_reference: Hash | None
    source_origin: Literal["NATIVE_OS", "FIXTURE"]
    trust: Literal[
        "OBSERVED_EVENT", "MODEL_INFERENCE", "HUMAN_FEEDBACK", "VERIFIED_TEST_RESULT", "UNKNOWN"
    ]
    category: Literal["INVESTIGATION_OUTCOME", "OPERATOR_REVIEW", "SIMULATION_OUTCOME"]
    processing_status: str = Field(max_length=32)
    diagnostic_label: Literal["UNLABELED"] = "UNLABELED"
    authority: Literal["NONE"] = "NONE"


def project_feedback(monitor) -> dict:
    """Validate underlying stores every time; materialize nothing and never interpret notes."""
    monitor.store.verify_audit()
    with monitor.store.database.transaction(write=False) as c:
        rows = list(c.execute("SELECT * FROM monitor_findings ORDER BY id LIMIT 513"))
    if len(rows) > 512:
        raise ValueError("FEEDBACK_PROJECTION_LIMIT_EXCEEDED")
    items = []
    findings = {}
    for row in rows:
        finding = monitor.store._decode(row)
        validate_finding(monitor.pipeline, finding)
        findings[finding.finding_id] = finding
        result = json.loads(row["result"]) if row["result"] else None
        core = {
            "incident_id": finding.incident_id,
            "finding_reference": finding.finding_id,
            "finding_digest": finding.digest,
            "evidence_references": finding.evidence_references,
            "provenance_references": finding.provenance,
            "result_reference": row["result_digest"],
            "source_origin": finding.input_origin,
            "trust": "MODEL_INFERENCE"
            if result and result.get("mode") == "REAL_LLM"
            else "VERIFIED_TEST_RESULT"
            if result and result.get("mode") == "SCRIPTED"
            else "OBSERVED_EVENT"
            if finding.input_origin == "NATIVE_OS"
            else "VERIFIED_TEST_RESULT",
            "category": "INVESTIGATION_OUTCOME",
            "processing_status": row["status"],
        }
        # Reuse Snapshot JSON canonicalization, including tuple and UUID normalization.
        normalized = OutcomeFeedback(feedback_id="0" * 64, **core).model_dump(
            mode="json", exclude={"feedback_id"}
        )
        items.append(OutcomeFeedback(feedback_id=content_digest_payload(normalized), **core))
    for record in monitor.simulation.records():
        finding = findings.get(record.request.finding_id)
        if finding is None:
            raise ValueError("FEEDBACK_FINDING_MISSING")
        # Reference integrity is checked against the original completed investigation.
        with monitor.store.database.transaction(write=False) as c:
            monitor.simulation._verify(c, record)
        if record.approval.decision is None:
            continue
        core = {
            "incident_id": finding.incident_id,
            "finding_reference": finding.finding_id,
            "finding_digest": finding.digest,
            "evidence_references": finding.evidence_references,
            "provenance_references": finding.provenance,
            "result_reference": content_digest_payload(record.model_dump(mode="json")),
            "source_origin": finding.input_origin,
            "trust": "HUMAN_FEEDBACK"
            if record.actor_assurance == "OS_PEER_IDENTITY"
            else "VERIFIED_TEST_RESULT",
            "category": "OPERATOR_REVIEW",
            "processing_status": record.approval.status.value.upper(),
        }
        normalized = OutcomeFeedback(feedback_id="0" * 64, **core).model_dump(
            mode="json", exclude={"feedback_id"}
        )
        items.append(OutcomeFeedback(feedback_id=content_digest_payload(normalized), **core))
        if record.status in ("SIMULATED", "UNCERTAIN", "DENIED"):
            # Human consent and observed test outcome are distinct facts/trust levels.
            outcome = core | {
                "category": "SIMULATION_OUTCOME",
                "processing_status": record.status,
                "trust": "VERIFIED_TEST_RESULT" if record.status == "SIMULATED" else "UNKNOWN",
            }
            normalized = OutcomeFeedback(feedback_id="0" * 64, **outcome).model_dump(
                mode="json", exclude={"feedback_id"}
            )
            items.append(OutcomeFeedback(feedback_id=content_digest_payload(normalized), **outcome))
    from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop

    loop = RuntimeFeedbackLoop(monitor)
    loop.active_records()  # Validate current diagnostic feedback source bindings.
    payload = {
        "contract_version": "soc-runtime-feedback-projection:v2",
        "items": [i.model_dump(mode="json") for i in sorted(items, key=lambda i: i.feedback_id)],
        "automatic_changes": "DISABLED",
        "inference_status": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
        "ground_truth_generation": "DISABLED",
        "human_diagnostic_feedback": [v.model_dump(mode="json") for v in loop.records()],
        "candidate_generation": "EXPLICIT_OFFLINE_ONLY",
        "promotion": "NOT_CONNECTED",
    }
    return payload | {"projection_digest": content_digest_payload(payload)}
