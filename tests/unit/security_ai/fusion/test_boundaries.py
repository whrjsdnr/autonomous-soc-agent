from datetime import timedelta
from uuid import uuid4

import pytest
from tests.fusion_support import fusion_input, model_bindings
from tests.scenarios.test_security_ai_fusion import authentication_features
from tests.scenarios.test_security_ai_packaging import network_feature

from soc_agent.approval import ApprovalManager
from soc_agent.assessment.models import ThreatAssessment
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
from soc_agent.security_ai.fusion import FusionIdentityCollision, MultiModelFusionEngine
from soc_agent.security_ai.network.classifier import NetworkAttackClassifier
from soc_agent.security_ai.packaging.forest import NumericForest
from soc_agent.security_ai.packaging.package import ModelPackage
from soc_agent.state import Evidence, Hypothesis, IncidentState, Observation
from soc_agent.state.evidence import utc_now
from soc_agent.tools import Tool, ToolRegistry


def test_no_side_effects_no_inference_and_immutable_inputs(monkeypatch):
    bindings = model_bindings()
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="existing",
        summary="existing record",
        raw_data="{}",
        observed_at=utc_now(),
    )
    state = state.add_evidence(evidence)
    state = state.add_observation(
        Observation(statement="existing fact", supporting_evidence_ids=(evidence.evidence_id,))
    )
    state = state.add_hypothesis(
        Hypothesis(
            statement="existing interpretation",
            confidence=0.2,
            supporting_evidence_ids=(evidence.evidence_id,),
        )
    )
    inputs = (fusion_input(bindings["network_classifier"], network_feature("stream"), state),)
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    approvals, policy, registry = ApprovalManager(), PolicyEngine(), SecurityAIRegistry()
    executor = GovernedExecutor(registry=ToolRegistry(), policy=policy, approvals=approvals)
    state_before, inputs_before = (
        state.model_dump_json(),
        tuple(i.model_dump_json() for i in inputs),
    )
    policy_before, approvals_before = vars(policy).copy(), approvals.list()
    attempts_before, registry_before = executor._attempted.copy(), registry.list()

    def forbidden(*args, **kwargs):
        pytest.fail("Fusion crossed a state, execution, registration or inference boundary")

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    for cls, name in (
        (Evidence, "__init__"),
        (Observation, "__init__"),
        (Hypothesis, "__init__"),
        (ThreatAssessment, "__init__"),
        (IncidentState, "__init__"),
        (IncidentState, "add_evidence"),
        (IncidentState, "add_observation"),
        (IncidentState, "add_hypothesis"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (ApprovalManager, "reject"),
        (Tool, "execute"),
        (GovernedExecutor, "execute"),
        (GovernedExecutor, "request_approval"),
        (MockLLMClient, "generate_structured"),
        (SecurityAIRegistry, "register"),
        (SecurityAI, "predict"),
        (ModelPackage, "predict"),
        (NetworkAttackClassifier, "predict"),
        (NumericForest, "score_samples"),
        (IsolationForest, "fit"),
        (StandardScaler, "fit"),
    ):
        monkeypatch.setattr(cls, name, forbidden)
    result = engine.fuse(incident_id=state.incident_id, inputs=inputs)
    assert result.contributions
    assert state.model_dump_json() == state_before
    assert tuple(i.model_dump_json() for i in inputs) == inputs_before
    assert vars(policy) == policy_before
    assert approvals.list() == approvals_before
    assert executor._attempted == attempts_before
    assert registry.list() == registry_before


def test_authentication_windows_do_not_merge():
    bindings, state = model_bindings(), IncidentState()
    features = (authentication_features(window=0), authentication_features(window=1))
    assert features[0].input_fingerprint == features[1].input_fingerprint
    inputs = tuple(fusion_input(bindings["authentication_anomaly"], f, state) for f in features)
    result = MultiModelFusionEngine(
        tuple(bindings.values()), expected_models=("authentication_anomaly",)
    ).fuse(incident_id=state.incident_id, inputs=inputs)
    assert len(result.contributions) == len(result.correlation_groups) == 2
    assert result.summary.unique_source_record_count == 84
    assert result.summary.cross_domain_state == "not_applicable"


@pytest.mark.parametrize("domain", ("network_classifier", "authentication_anomaly"))
def test_offline_stream_same_measurements_are_distinct_sources(domain):
    bindings, state = model_bindings(), IncidentState()
    features = tuple(
        authentication_features(kind=k)
        if domain == "authentication_anomaly"
        else network_feature(k)
        for k in ("dataset", "stream")
    )
    assert features[0].input_fingerprint == features[1].input_fingerprint
    inputs = tuple(fusion_input(bindings[domain], f, state) for f in features)
    result = MultiModelFusionEngine(tuple(bindings.values()), expected_models=(domain,)).fuse(
        incident_id=state.incident_id, inputs=inputs
    )
    assert len(result.contributions) == len(result.correlation_groups) == 2
    assert result.agreement_state == "insufficient"
    assert len(result.deduplicated_signals) == 2


def test_new_extraction_uuid_replay_ignored_but_aliases_preserved():
    bindings, state = model_bindings(), IncidentState()
    features = network_feature("stream")
    first = fusion_input(bindings["network_classifier"], features, state)
    sources = tuple(
        s.model_copy(update={"record_id": uuid4()}) for s in features.provenance.sources
    )
    replay_features = features.model_copy(
        update={
            "feature_set_id": uuid4(),
            "created_at": features.created_at + timedelta(seconds=1),
            "provenance": features.provenance.model_copy(update={"sources": sources}),
        }
    )
    replay = fusion_input(bindings["network_classifier"], replay_features, state)
    engine = MultiModelFusionEngine(
        tuple(bindings.values()), expected_models=("network_classifier",)
    )
    original = engine.fuse(incident_id=state.incident_id, inputs=(first,))
    repeated = engine.fuse(incident_id=state.incident_id, inputs=(first, replay))
    assert original.fusion_id == repeated.fusion_id
    assert original.summary == repeated.summary
    assert len(repeated.contributions) == len(repeated.deduplicated_signals) == 1
    assert len(repeated.signals) == 2


def test_same_logical_source_and_time_collision_rejected():
    bindings, state = model_bindings(), IncidentState()
    features = network_feature("stream")
    first = fusion_input(bindings["network_classifier"], features, state)
    source = features.provenance.sources[0].model_copy(update={"content_digest": "a" * 64})
    changed = features.model_copy(
        update={"provenance": features.provenance.model_copy(update={"sources": (source,)})}
    )
    other = fusion_input(bindings["network_anomaly"], changed, state)
    engine = MultiModelFusionEngine(tuple(bindings.values()), expected_models=tuple(bindings))
    with pytest.raises(FusionIdentityCollision, match="logical source"):
        engine.fuse(incident_id=state.incident_id, inputs=(first, other))
