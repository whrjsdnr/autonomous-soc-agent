"""Versioned analytical rules; these never grant execution permission."""

from enum import StrEnum

from soc_agent.assessment.models import ThreatAssessment
from soc_agent.security_ai.fusion.models import FusionResult
from soc_agent.state import Severity

RULE_VERSION = "incident-decision:v1"


class DecisionOutcome(StrEnum):
    INVESTIGATE = "further_investigation"
    INSUFFICIENT = "insufficient_basis"
    SUSPICIOUS = "suspicion_for_review"
    NO_ADDITIONAL_ALERT = "no_additional_alert_basis"


def evaluate(
    assessment: ThreatAssessment, fusion: FusionResult | None
) -> tuple[DecisionOutcome, tuple[str, ...], tuple[str, ...]]:
    """Conservative routing of advisory indicators, never semantic proof of attack."""
    concern = assessment.severity != Severity.INFO
    reasons = []
    followup = []
    if concern:
        reasons.append("assessment_advisory_concern")
        followup.append("Verify the assessment interpretation against its source evidence.")
    if not assessment.supporting_observation_ids and not assessment.supporting_hypothesis_ids:
        followup.append(
            "Assessment has no linked observation or hypothesis; inspect source evidence."
        )
    if fusion is None:
        reasons.append("fusion_not_supplied")
        alert = False
    else:
        alert = any(c.decision not in ("BENIGN", "normal") for c in fusion.contributions)
        if alert:
            reasons.append("model_alert_requires_evidence")
            followup.append("Collect or verify evidence for model-derived indications.")
        else:
            reasons.append("no_model_alert_in_supplied_inputs")
        for entry in fusion.coverage:
            if entry.status != "observed":
                reasons.append(f"coverage:{entry.model_kind}:{entry.status}")
                followup.append(f"Review missing coverage: {entry.model_kind} ({entry.status}).")
        if any("benign_with_anomaly" in g.network_relations for g in fusion.correlation_groups):
            reasons.append("benign_anomaly_disagreement")
            followup.append(
                "Review BENIGN and anomaly outputs separately; neither cancels the other."
            )
        if fusion.summary.cross_domain_state == "unverified":
            reasons.append("cross_domain_unverified")
            followup.append(
                "Network and authentication groups have no verified common actor or attack."
            )
        if fusion.contributions and concern != alert:
            reasons.append("assessment_model_difference")
            followup.append(
                "Review differing assessment and model indications without overwriting either."
            )
    if concern:
        outcome = DecisionOutcome.SUSPICIOUS
    elif alert:
        outcome = DecisionOutcome.INVESTIGATE
    elif followup:
        outcome = DecisionOutcome.INSUFFICIENT
    else:
        outcome = DecisionOutcome.NO_ADDITIONAL_ALERT
    return outcome, tuple(sorted(reasons)), tuple(sorted(set(followup)))
