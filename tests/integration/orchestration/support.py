"""Explicit external human driver and test-only inference at real integration boundaries."""

from soc_agent.llm import MockLLMClient
from soc_agent.response.advisory import CandidateIntent
from soc_agent.security_ai import (
    MockSecurityAI,
    SecurityAIInvestigator,
    SecurityAIModelMetadata,
    SecurityAIRegistry,
    SecurityAISelector,
)
from soc_agent.security_ai.features import FeatureSet, record_from_evidence
from soc_agent.security_ai.fusion import FusionInput, MultiModelFusionEngine
from soc_agent.security_ai.network.schema import NetworkFeatureExtractor
from tests.fusion_support import fusion_input, model_bindings
from tests.unit.investigation_runtime.conftest import decision_ready, review_for
from tests.unit.promotion.conftest import approve, promoted

NETWORK_EVENT = {
    "duration_us": 200000.0,
    "fwd_packets": 100,
    "bwd_packets": 5,
    "fwd_bytes": 10000,
    "bwd_bytes": 200,
}


class ModelAnalysis:
    """Test-only model output; actual selection, wrapper, signal and fusion validation."""

    def __init__(self):
        self.binding = model_bindings()["network_classifier"]
        self.runs = []

    async def __call__(self, state):
        source = record_from_evidence(
            state=state,
            evidence_id=state.evidence[0].evidence_id,
            record_type="network_flow",
            record_schema_version="1.0.0",
        )
        features = NetworkFeatureExtractor().extract(source, state=state)
        sample = fusion_input(self.binding, features, state).signal
        mock = MockSecurityAI(
            metadata=SecurityAIModelMetadata(
                name=sample.model_name,
                version=sample.model_version,
                description="Test-only classifier",
                task_type="classification",
                input_type="network_flow",
            ),
            input_model=FeatureSet,
            responses=[
                {
                    "prediction": sample.prediction,
                    "confidence": sample.confidence,
                    "scores": sample.scores_payload(),
                    "explanation": sample.explanation_payload(),
                }
            ],
        )
        registry = SecurityAIRegistry()
        registry.register(mock.model)
        selector_llm = MockLLMClient(
            [
                {
                    "decision": "run_ai",
                    "goal": "Inspect network source",
                    "reason": "Advisory model context",
                    "selections": [
                        {
                            "model_name": sample.model_name,
                            "model_input": features.model_dump(mode="json"),
                            "purpose": "Classify source",
                        }
                    ],
                }
            ]
        )
        selection = await SecurityAISelector(llm_client=selector_llm, registry=registry).select(
            incident=state
        )
        investigation = await SecurityAIInvestigator(registry=registry).execute(
            incident=state,
            selection_plan=selection,
            source_evidence={s.step_id: (state.evidence[0].evidence_id,) for s in selection.steps},
        )
        assert mock.call_count == 1 and len(investigation.signals) == 1
        fusion = MultiModelFusionEngine((self.binding,), ("network_classifier",)).fuse(
            incident_id=state.incident_id,
            inputs=(FusionInput(signal=investigation.signals[0], features=features),),
        )
        self.runs.append((selection, investigation, fusion))
        return fusion


def fusion_llm(case, count=2):
    """Fusion mode cannot add model predictions as observations."""
    response = {
        "observations": [],
        "hypotheses": [],
        "assessment": {
            "severity": "high",
            "confidence": 0.2,
            "summary": "Unverified model concern",
            "supporting_evidence_ids": [str(case.initial.evidence[0].evidence_id)],
        },
    }
    client = MockLLMClient([response] * count)
    case.llm.generate_structured = client.generate_structured
    return client


async def plan_response(case, *, write=False, analyze=True):
    if analyze:
        await decision_ready(case)
    review = review_for(case)
    await case.runtime.advance(case.incident_id, review=review)
    state = case.store.load(case.incident_id).state
    tool = "test_response" if write else "inspect_logs"
    candidate = CandidateIntent(
        candidate_tool=tool,
        proposed_input={"target": "host_a"},
        purpose="Explicit human response consideration",
        rationale="Review source evidence",
        evidence_ids=(state.evidence[0].evidence_id,),
    )
    result = await case.runtime.advance(case.incident_id, candidates=(candidate,))
    assert result.waiting_for_human
    plan = case.runtime.artifacts(case.incident_id).response_plan
    workflow = (
        None,
        plan,
        case.policy,
        case.promotion_service,
        case.approvals,
        case.bridge,
        case.authority,
    )
    return workflow


async def promote_response(case, *, write=False, approve_write=True, analyze=True):
    workflow = await plan_response(case, write=write, analyze=analyze)
    value = promoted(workflow, "test_response" if write else "inspect_logs")
    approval = approve(workflow, value) if write and approve_write else None
    result = await case.runtime.advance(
        case.incident_id, promoted=value, approval_id=approval.approval_id if approval else None
    )
    return workflow, value, result
