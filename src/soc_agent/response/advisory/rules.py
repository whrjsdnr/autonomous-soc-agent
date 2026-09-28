"""Planning restrictions are advisory routing, never execution policy overrides."""

from soc_agent.decision import IncidentDecision
from soc_agent.decision.rules import DecisionOutcome
from soc_agent.review.models import HumanReviewRecord, ReviewOutcome
from soc_agent.tools import ToolMetadata, ToolPermission

READ_PERMISSIONS = (
    ToolPermission.SYSTEM_READ,
    ToolPermission.NETWORK_READ,
    ToolPermission.FILE_READ,
)


def is_investigation(metadata: ToolMetadata) -> bool:
    return metadata.permission in READ_PERMISSIONS


def dispositions(decision: IncidentDecision, review: HumanReviewRecord) -> tuple[str, ...]:
    result = []
    if review.outcome == ReviewOutcome.REJECTED:
        # Actual enum means state-change rejection, not rejection of analytical truth.
        result.append("review_rejected_state_change_conservative_planning_stop")
    if review.outcome == ReviewOutcome.INVESTIGATE:
        result.append("human_requested_investigation")
    if not decision.evidence_ids:
        result.append("insufficient_evidence")
    if decision.model_derived_context is not None:
        result.append("model_context_not_evidence")
        if decision.outcome == DecisionOutcome.INVESTIGATE:
            result.append("model_alert_requires_grounding")
    if decision.additional_investigation_required:
        result.append("additional_investigation_required")
    if set(decision.applied_rules) & {"assessment_model_difference", "benign_anomaly_disagreement"}:
        result.append("assessment_model_disagreement_requires_review")
    return tuple(sorted(result))


def defer_response(decision: IncidentDecision, review: HumanReviewRecord) -> bool:
    return (
        review.outcome == ReviewOutcome.INVESTIGATE
        or not decision.evidence_ids
        or decision.outcome != DecisionOutcome.SUSPICIOUS
    )
