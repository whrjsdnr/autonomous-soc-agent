"""Synthetic auth events through grouped fitting and provenance-independent inference."""

import json

import pytest
from tests.authentication_support import fixture_examples

from soc_agent.adaptive import AdaptiveInvestigationPlanner
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
from soc_agent.security_ai.authentication import AnomalyTrainingConfig, train_authentication
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def test_authentication_offline_stream_bridge(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Authentication pipeline crossed an agent/governance boundary")

    for cls, method in (
        (MockLLMClient, "generate_structured"),
        (Tool, "execute"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (GovernedExecutor, "execute"),
        (AdaptiveInvestigationPlanner, "replan"),
        (SecurityAI, "predict"),
        (SecurityAIRegistry, "register"),
    ):
        monkeypatch.setattr(cls, method, forbidden)
    state = IncidentState()
    before = state.model_dump_json()
    offline = fixture_examples("dataset")
    online = fixture_examples("stream")
    result = train_authentication(offline, config=AnomalyTrainingConfig(n_estimators=16))
    assert len(offline) == 30
    assert len(result.metadata.baseline_indices) == 9
    for a, b in zip(offline, online, strict=True):
        assert a.features.input_fingerprint == b.features.input_fingerprint
        assert a.features.provenance != b.features.provenance
        assert result.detector.predict(a.features) == result.detector.predict(b.features)
        assert not hasattr(result.detector.predict(a.features), "attack_type")
    assert state.model_dump_json() == before
    assert result.metadata.persistence == "in_memory_only"
    assert result.metadata.test.normal_support == result.metadata.test.anomaly_support == 3
    print(json.dumps({"fixture_only": True, "test": result.metadata.test.model_dump()}))
