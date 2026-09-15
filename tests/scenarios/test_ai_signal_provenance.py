"""Observed evidence and model predictions retain distinct lifecycles."""

import json

import pytest
from pydantic import BaseModel, ConfigDict

from soc_agent.assessment.models import ThreatAssessment
from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIModelMetadata,
    SecurityAITaskType,
    build_ai_signal_context,
    create_ai_signal,
)
from soc_agent.state import Evidence, IncidentState, Observation
from soc_agent.state.evidence import utc_now


class AuthFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failures: int


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "predictions,versions,task",
    [
        (("credential_attack",), ("1.0.0",), SecurityAITaskType.CLASSIFICATION),
        (("anomalous",), ("1.0.0",), SecurityAITaskType.ANOMALY_DETECTION),
        (("malicious", "benign"), ("1.0.0", "1.0.0"), SecurityAITaskType.CLASSIFICATION),
        (("malicious", "malicious"), ("1.0.0", "1.1.0"), SecurityAITaskType.CLASSIFICATION),
    ],
)
async def test_evidence_result_signal_lifecycle(
    predictions: tuple[str, ...], versions: tuple[str, ...], task: SecurityAITaskType
) -> None:
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="auth.log",
        summary="43 failed authentication attempts",
        raw_data="43 fixture records",
        observed_at=utc_now(),
    )
    state = state.add_evidence(evidence).add_observation(
        Observation(
            statement="43 failures recorded", supporting_evidence_ids=(evidence.evidence_id,)
        )
    )
    assessment = ThreatAssessment(
        incident_id=state.incident_id,
        severity="low",
        confidence=0.4,
        summary="Further investigation needed",
        supporting_evidence_ids=(evidence.evidence_id,),
    )
    before, assessment_before = state.model_dump_json(), assessment.model_dump_json()
    signals = []
    for index, (prediction, version) in enumerate(zip(predictions, versions, strict=True)):
        anomaly = task == SecurityAITaskType.ANOMALY_DETECTION
        name = "network_anomaly_mock" if anomaly else "network_ids_mock"
        if predictions == ("malicious", "benign") and index:
            name = "other_ids_mock"
        confidence = None if anomaly else (0.94 if len(predictions) == 1 else (0.91, 0.82)[index])
        mock = MockSecurityAI(
            metadata=SecurityAIModelMetadata(
                name=name,
                version=version,
                description="Scenario fixture",
                task_type=task,
                input_type="authentication_event",
            ),
            input_model=AuthFeatures,
            responses=[
                {
                    "prediction": prediction,
                    "confidence": confidence,
                    "scores": {"anomaly_score": 0.87} if anomaly else {},
                }
            ],
        )
        result = await mock.model.predict(
            {
                "incident_id": state.incident_id,
                "input": {"failures": 43},
            }
        )
        signal = create_ai_signal(result, state=state, source_evidence_ids=(evidence.evidence_id,))
        assert signal.source_result_id == result.result_id
        assert signal.incident_id == state.incident_id
        assert signal.source_evidence_ids == (evidence.evidence_id,)
        assert signal.model_name == name and signal.model_version == version
        assert signal.task_type == task and signal.confidence == confidence
        assert signal.prediction == prediction
        assert not isinstance(signal, (Evidence, Observation))
        if anomaly:
            assert signal.scores_payload() == {"anomaly_score": 0.87}
        signals.append(signal)
        foreign = IncidentState()
        with pytest.raises(ValueError):
            create_ai_signal(result, state=foreign, source_evidence_ids=(evidence.evidence_id,))
        assert mock.call_count == 1
    context = json.loads(build_ai_signal_context(tuple(signals), state=state))
    records = next(iter(context.values()))
    assert len(records) == len(predictions)
    assert tuple(record["prediction"] for record in records) == predictions
    assert tuple(record["model"]["version"] for record in records) == versions
    assert state.model_dump_json() == before
    assert state.hypotheses == ()
    assert assessment.model_dump_json() == assessment_before
