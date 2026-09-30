from datetime import timedelta
from uuid import uuid4

import pytest

from soc_agent.assessment import AssessmentResult, ThreatAssessment
from soc_agent.review.errors import StaleSnapshotError
from soc_agent.state import Hypothesis, Observation


def assessment(state):
    return AssessmentResult(
        incident_state=state,
        threat_assessment=ThreatAssessment(
            incident_id=state.incident_id,
            severity="high",
            confidence=0.8,
            summary="Advisory",
            supporting_evidence_ids=(state.evidence[0].evidence_id,),
        ),
    )


def analyzed(state):
    ids = (state.evidence[0].evidence_id,)
    return state.add_observation(
        Observation(statement="Source observation", supporting_evidence_ids=ids)
    ).add_hypothesis(
        Hypothesis(statement="Unverified explanation", confidence=0.4, supporting_evidence_ids=ids)
    )


def test_analysis_cas_appends_only_and_rejects_stale_anchor(runtime_case):
    c = runtime_case()
    before = c.store.load(c.incident_id)
    result = assessment(analyzed(before.state))
    after = c.store.append_assessment(before.anchor, result)
    assert after.state == result.incident_state and after.anchor.revision == 1
    assert after.state.severity == before.state.severity
    assert after.state.evidence == before.state.evidence
    with pytest.raises(StaleSnapshotError):
        c.store.append_assessment(before.anchor, result)
    assert c.store.append_assessment(after.anchor, result) == after
    assert len(c.store.events()) == 2


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "severity",
        "confidence",
        "evidence",
        "evidence_append",
        "evidence_remove",
        "created_at",
    ],
)
def test_protected_state_mutation_rejected_atomically(runtime_case, field):
    c = runtime_case()
    before = c.store.load(c.incident_id)
    state = analyzed(before.state)
    updates = {
        "status": "closed",
        "severity": "critical",
        "confidence": 0.99,
        "evidence": (state.evidence[0].model_copy(update={"raw_data": "forged"}),),
        "evidence_append": (
            *state.evidence,
            state.evidence[0].model_copy(update={"evidence_id": uuid4()}),
        ),
        "evidence_remove": (),
        "created_at": state.created_at - timedelta(seconds=1),
    }
    key = "evidence" if field.startswith("evidence") else field
    forged = assessment(state).model_copy(
        update={"incident_state": state.model_copy(update={key: updates[field]})}
    )
    with pytest.raises(ValueError):
        c.store.append_assessment(before.anchor, forged)
    assert c.store.load(c.incident_id) == before
    assert len(c.store.events()) == 1


@pytest.mark.parametrize("mutation", ["overwrite", "remove", "bad_reference", "timestamp_only"])
def test_analysis_is_append_only_and_revalidated(runtime_case, mutation):
    c = runtime_case()
    before = c.store.load(c.incident_id)
    before = c.store.append_assessment(before.anchor, assessment(analyzed(before.state)))
    state = before.state
    if mutation == "overwrite":
        updated = state.model_copy(
            update={
                "observations": (
                    state.observations[0].model_copy(update={"statement": "Changed fact"}),
                )
            }
        )
    elif mutation == "remove":
        updated = state.model_copy(update={"hypotheses": ()})
    elif mutation == "bad_reference":
        updated = state.model_copy(
            update={
                "observations": (
                    *state.observations,
                    Observation(statement="Invalid link", supporting_evidence_ids=(uuid4(),)),
                )
            }
        )
    else:
        updated = state.model_copy(update={"updated_at": state.updated_at + timedelta(seconds=1)})
    forged = assessment(state).model_copy(update={"incident_state": updated})
    with pytest.raises(ValueError):
        c.store.append_assessment(before.anchor, forged)
    assert c.store.load(c.incident_id) == before
    assert len(c.store.events()) == 2


def test_fusion_lineage_preserved_but_cannot_publish_new_facts(runtime_case):
    from soc_agent.assessment import FusionAssessmentResult
    from soc_agent.investigation.runtime.models import WorkflowArtifacts
    from soc_agent.security_ai.fusion import MultiModelFusionEngine

    c = runtime_case()
    before = c.store.load(c.incident_id)
    fusion = MultiModelFusionEngine((), ("network_classifier",)).fuse(
        incident_id=c.incident_id, inputs=()
    )
    result = FusionAssessmentResult(
        **assessment(before.state).model_dump(), model_derived_context=fusion
    )
    assert c.store.append_assessment(before.anchor, result) == before
    saved = WorkflowArtifacts(snapshot=before.anchor, assessment=result)
    restored = WorkflowArtifacts.model_validate_json(saved.model_dump_json())
    assert restored.assessment.model_derived_context == fusion
    forged = result.model_copy(update={"incident_state": analyzed(before.state)})
    with pytest.raises(ValueError, match="cannot publish facts"):
        c.store.append_assessment(before.anchor, forged)
    assert c.store.load(c.incident_id) == before
