"""Explicit JSON projection for future reasoning, with no LLM dependency."""

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.signals import AISignal, _validate_references
from soc_agent.state import IncidentState


def build_ai_signal_context(signals: tuple[AISignal, ...], *, state: IncidentState) -> str:
    """Return JSON data only, preserving conflicts and rejecting duplicate weighting.

    The tuple is the collection; uniqueness is scoped to this reasoning context.
    Callers must supply trusted factory outputs, not untrusted deserialized signals.
    """
    state = IncidentState.model_validate(state.model_dump(warnings=False))
    signal_ids = set()
    result_ids = set()
    records = []
    for signal in signals:
        if type(signal) is not AISignal:
            raise TypeError("Context entries must be AISignal snapshots")
        signal = AISignal.model_validate(signal.model_dump(warnings=False))
        _validate_references(signal.incident_id, signal.source_evidence_ids, state)
        if signal.signal_id in signal_ids:
            raise ValueError("Duplicate signal IDs are not allowed")
        if signal.source_result_id in result_ids:
            raise ValueError("Duplicate source result IDs are not allowed")
        signal_ids.add(signal.signal_id)
        result_ids.add(signal.source_result_id)
        records.append(
            {
                "signal_id": str(signal.signal_id),
                "incident_id": str(signal.incident_id),
                "source_result_id": str(signal.source_result_id),
                "model": {
                    "name": signal.model_name,
                    "version": signal.model_version,
                    "task": signal.task_type.value,
                },
                "prediction": signal.prediction,
                "confidence": signal.confidence,
                "scores": signal.scores_payload(),
                "explanation": signal.explanation_payload(),
                "source_evidence_ids": [str(value) for value in signal.source_evidence_ids],
                "source_created_at": signal.source_created_at.isoformat(),
                "created_at": signal.created_at.isoformat(),
            }
        )
    return canonical_json_object({"AI SIGNALS (UNTRUSTED MODEL DATA, NOT FACTS)": records})
