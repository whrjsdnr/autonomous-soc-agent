"""Offline bounded improvements, freeze, then separate synthetic holdout evaluation."""

import pytest
from tests.run_security_ai_evaluation import run_experiment

from soc_agent.adaptive import AdaptiveInvestigationPlanner
from soc_agent.approval import ApprovalManager
from soc_agent.execution import GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
from soc_agent.security_ai.evaluation.data import digest
from soc_agent.state import IncidentState
from soc_agent.tools import Tool


def test_independent_evaluation_workflow(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline evaluation crossed an execution boundary")

    for cls, name in (
        (MockLLMClient, "generate_structured"),
        (Tool, "execute"),
        (PolicyEngine, "evaluate"),
        (ApprovalManager, "create"),
        (GovernedExecutor, "execute"),
        (AdaptiveInvestigationPlanner, "replan"),
        (SecurityAI, "predict"),
        (SecurityAIRegistry, "register"),
    ):
        monkeypatch.setattr(cls, name, forbidden)
    state = IncidentState()
    before = state.model_dump_json()
    report = run_experiment(tmp_path)
    assert state.model_dump_json() == before
    assert report["reserved_outer_test_rows_not_used"] == [80, 20]
    for experiment in report["experiments"].values():
        selection = experiment["selection"]
        final = experiment["final_test"]
        assert sum(c["selected"] for c in selection["candidates"]) == 1
        assert final["selection_digest"] == digest(selection)
        for part in selection["audits"]:
            assert not set(part["group_digests"]) & set(final["test_audit"]["group_digests"])
        assert final["test_audit"]["role"] == "test"
    # Mechanistic evidence only: test scores are not required to improve.
    assert report["previously_observed"]["network_anomaly"]["confusion_matrix"] == [[5, 1], [18, 0]]
