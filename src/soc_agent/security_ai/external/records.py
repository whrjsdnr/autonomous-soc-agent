"""Companion records bind supplied core outputs; they never execute an assessment."""

from typing import Literal
from uuid import UUID

from soc_agent.assessment import AssessmentResult, FusionAssessmentResult
from soc_agent.decision import IncidentDecision
from soc_agent.review.models import StateAnchor
from soc_agent.security_ai.external.models import Hash, Snapshot, SourceEvidenceReference
from soc_agent.state.evidence import UTCTimestamp


class AssessmentRun(Snapshot):
    contract_version: Literal["soc-external-assessment-run:v2"] = "soc-external-assessment-run:v2"
    run_id: UUID
    incident_id: UUID
    input_anchor: StateAnchor
    output_anchor: StateAnchor
    context_digest: Hash
    core_result: AssessmentResult | FusionAssessmentResult
    assessment_reference: UUID
    created_at: UTCTimestamp
    validation_status: Literal["VALIDATED_FOR_ADVISORY"] = "VALIDATED_FOR_ADVISORY"


class ProvenanceReceipt(Snapshot):
    contract_version: Literal["soc-context-assessment-receipt:v2"] = (
        "soc-context-assessment-receipt:v2"
    )
    receipt_id: UUID
    context_digest: Hash
    assessment_run_id: UUID
    input_anchor: StateAnchor
    output_anchor: StateAnchor
    assessment_digest: Hash
    request_projection_digest: Hash
    fusion_digest: Hash | None = None
    source_evidence_references: tuple[SourceEvidenceReference, ...]
    disposition: Literal["READ_ONLY_ADVISORY"] = "READ_ONLY_ADVISORY"


class DecisionReceipt(Snapshot):
    contract_version: Literal["soc-context-decision-receipt:v2"] = "soc-context-decision-receipt:v2"
    receipt_id: UUID
    assessment_receipt_id: UUID
    assessment_run_id: UUID
    context_digest: Hash
    core_decision: IncidentDecision
    decision_digest: Hash
    input_anchor: StateAnchor
    output_anchor: StateAnchor
    disposition: Literal["READ_ONLY_ADVISORY"] = "READ_ONLY_ADVISORY"


class ResumeRequirement(Snapshot):
    """Exact expected lineage, supplied from a trusted caller, never inferred from absence."""

    contract_version: Literal["soc-external-resume:v2"] = "soc-external-resume:v2"
    run_id: UUID
    incident_id: UUID
    context_digest: Hash
    receipt_id: UUID
    receipt_digest: Hash
    input_anchor: StateAnchor
    output_anchor: StateAnchor
    decision_receipt_id: UUID | None = None
    decision_receipt_digest: Hash | None = None
