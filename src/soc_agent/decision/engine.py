"""Pure decision generation from completed, revalidated analysis."""

from pydantic import BaseModel, JsonValue

from soc_agent._json import canonical_json_object
from soc_agent.assessment.fusion import FusionAssessmentResult
from soc_agent.assessment.models import AssessmentResult, ThreatAssessment
from soc_agent.decision.models import IncidentDecision, fingerprint
from soc_agent.decision.rules import RULE_VERSION, evaluate
from soc_agent.state import IncidentState


def _snapshot(value: BaseModel) -> str:
    """Compare reference sets and record collections without incidental ordering."""
    unordered = {
        "evidence",
        "observations",
        "hypotheses",
        "supporting_evidence_ids",
        "supporting_observation_ids",
        "supporting_hypothesis_ids",
    }

    def normalize(item: JsonValue) -> JsonValue:
        if isinstance(item, dict):
            result = {key: normalize(value) for key, value in item.items()}
            for key in unordered & result.keys():
                values = result[key]
                if isinstance(values, list):
                    result[key] = sorted(values, key=lambda v: canonical_json_object({"v": v}))
            return result
        if isinstance(item, list):
            return [normalize(value) for value in item]
        return item

    return canonical_json_object(normalize(value.model_dump(mode="json")))


class IncidentDecisionEngine:
    def decide(
        self,
        state: IncidentState,
        assessment: ThreatAssessment,
        *,
        fusion_assessment: FusionAssessmentResult | None = None,
    ) -> IncidentDecision:
        # Dict round trips revalidate nested unchecked model_copy/model_construct values.
        result = AssessmentResult.model_validate(
            {
                "incident_state": state.model_dump(warnings=False),
                "threat_assessment": assessment.model_dump(warnings=False),
            }
        )
        state, assessment = result.incident_state, result.threat_assessment
        fusion = None
        if fusion_assessment is not None:
            retained = FusionAssessmentResult.model_validate(
                fusion_assessment.model_dump(warnings=False)
            )
            if _snapshot(retained.threat_assessment) != _snapshot(assessment) or _snapshot(
                retained.incident_state
            ) != _snapshot(state):
                raise ValueError(
                    "Fusion assessment must retain the supplied assessment and exact state snapshot"
                )
            fusion = retained.model_derived_context
        # Reference lists are sets semantically; normalize without changing caller objects.
        assessment = ThreatAssessment.model_validate(
            assessment.model_dump()
            | {
                name: tuple(sorted(set(getattr(assessment, name)), key=str))
                for name in (
                    "supporting_evidence_ids",
                    "supporting_observation_ids",
                    "supporting_hypothesis_ids",
                )
            }
        )
        observations = tuple(
            sorted(
                (
                    o
                    for o in state.observations
                    if o.observation_id in assessment.supporting_observation_ids
                ),
                key=lambda o: str(o.observation_id),
            )
        )
        hypotheses = tuple(
            sorted(
                (
                    h
                    for h in state.hypotheses
                    if h.hypothesis_id in assessment.supporting_hypothesis_ids
                ),
                key=lambda h: str(h.hypothesis_id),
            )
        )
        observations = tuple(
            type(o).model_validate(
                o.model_dump()
                | {
                    "supporting_evidence_ids": tuple(
                        sorted(set(o.supporting_evidence_ids), key=str)
                    )
                }
            )
            for o in observations
        )
        hypotheses = tuple(
            type(h).model_validate(
                h.model_dump()
                | {
                    "supporting_evidence_ids": tuple(
                        sorted(set(h.supporting_evidence_ids), key=str)
                    )
                }
            )
            for h in hypotheses
        )
        evidence_ids = set(assessment.supporting_evidence_ids)
        for item in (*observations, *hypotheses):
            evidence_ids.update(item.supporting_evidence_ids)
        outcome, rules, followup = evaluate(assessment, fusion)
        data: dict[str, JsonValue] = {
            "decision_version": "1.0.0",
            "rule_version": RULE_VERSION,
            "incident_id": str(state.incident_id),
            "outcome": outcome.value,
            "assessment": assessment.model_dump(mode="json"),
            "evidence_ids": [str(e) for e in sorted(evidence_ids, key=str)],
            "observations": [o.model_dump(mode="json") for o in observations],
            "hypotheses": [h.model_dump(mode="json") for h in hypotheses],
            "model_derived_context": fusion.model_dump(mode="json") if fusion else None,
            "applied_rules": list(rules),
            "rationale": [
                "Assessment severity is advisory; "
                "linked interpretations are not confirmed compromise."
            ],
            "uncertainties": [
                "Reference integrity does not prove semantic entailment or attack success.",
                "No additional alert basis does not establish safety or absence of compromise.",
            ],
            "additional_investigation_required": bool(followup),
            "investigation_reasons": list(followup),
            "review_reasons": [
                "Human review is required before using advisory analysis for any governed action.",
                *followup,
            ],
            "limitations": [
                "No state snapshot/version binding exists in ThreatAssessment; "
                "contemporaneity is unproven.",
                "Identity binds retained analysis, not source authenticity "
                "or unchanged historical evidence content.",
                "Assessment prose is untrusted advisory analysis; "
                "no semantic attack verification is performed.",
                *(fusion.limitations if fusion else ("Model coverage was not supplied.",)),
            ],
        }
        return IncidentDecision.model_validate(data | {"decision_id": fingerprint(data)})
