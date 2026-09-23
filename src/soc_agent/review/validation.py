"""Reuse existing reference/lineage validation, without generating another decision."""

from pydantic import BaseModel

from soc_agent.assessment.fusion import validate_assessment_fusion
from soc_agent.assessment.models import AssessmentResult
from soc_agent.decision import IncidentDecision
from soc_agent.review.errors import ReviewError
from soc_agent.state import IncidentState


def checked[T: BaseModel](model: type[T], value: T) -> T:
    if type(value) is not model:
        raise ReviewError(f"Expected exact {model.__name__} contract")
    return model.model_validate(value.model_dump(warnings=False))


def validate_decision(state: IncidentState, decision: IncidentDecision) -> None:
    AssessmentResult.model_validate(
        {
            "incident_state": state.model_dump(),
            "threat_assessment": decision.assessment.model_dump(),
        }
    )
    if state.incident_id != decision.incident_id:
        raise ReviewError("Decision belongs to another incident")
    evidence_ids = set(decision.assessment.supporting_evidence_ids)
    for records, originals, refs, key in (
        (
            decision.observations,
            state.observations,
            decision.assessment.supporting_observation_ids,
            "observation_id",
        ),
        (
            decision.hypotheses,
            state.hypotheses,
            decision.assessment.supporting_hypothesis_ids,
            "hypothesis_id",
        ),
    ):
        by_id = {getattr(item, key): item for item in originals}
        if len(records) != len(refs) or {getattr(item, key) for item in records} != set(refs):
            raise ReviewError("Decision interpretation references mismatch")
        for item in records:
            source = by_id[getattr(item, key)]
            if item.model_dump(exclude={"supporting_evidence_ids"}) != source.model_dump(
                exclude={"supporting_evidence_ids"}
            ) or set(item.supporting_evidence_ids) != set(source.supporting_evidence_ids):
                raise ReviewError("Decision interpretation differs from state")
            evidence_ids.update(item.supporting_evidence_ids)
    if set(decision.evidence_ids) != evidence_ids:
        raise ReviewError("Decision evidence references mismatch")
    if decision.model_derived_context is not None:
        validate_assessment_fusion(decision.model_derived_context, state)
