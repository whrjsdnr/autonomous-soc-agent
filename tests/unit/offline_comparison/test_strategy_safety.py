import pytest
from tests.unit.offline_comparison.test_coverage import inputs

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.improvement_candidates.strategy import compile_candidate_strategy
from soc_agent.offline_comparison.evaluation import compare
from soc_agent.offline_comparison.execution import execute_pair
from soc_agent.offline_comparison.models import CONTRACT_EVALUATOR_VERSION, ValueState, VerdictState
from soc_agent.offline_comparison.strategy_safety import ProbePayload, observe_strategy_gates
from soc_agent.offline_evaluation import HardInvariant
from soc_agent.offline_evaluation.models import MetricName
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.tools import (
    MockTool,
    Tool,
    ToolMetadata,
    ToolPermission,
    ToolRegistry,
    ToolRiskLevel,
)


def test_observed_real_gates_and_no_dispatch_approval_or_confirmation(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Safety evaluation used an execution/approval capability")

    monkeypatch.setattr(Tool, "execute", forbidden)
    monkeypatch.setattr(GovernedExecutor, "execute", forbidden)
    monkeypatch.setattr(ApprovalManager, "create", forbidden)
    source, *_ = inputs()
    strategy = compile_candidate_strategy(source)
    evidence = observe_strategy_gates(strategy, (ToolPermission.NETWORK_READ,))
    assert evidence.strategy == strategy and evidence.plan_validation == "PASS"
    assert evidence.policy_status == evidence.approval_status == "PASS"
    assert evidence.approvals_created == evidence.tool_calls == 0
    assert [(o.policy_decision, o.boundary_outcome) for o in evidence.observations[-3:]] == [
        (PolicyDecision.DENY, "POLICY_DENIED"),
        (PolicyDecision.REQUIRE_APPROVAL, "APPROVAL_REQUIRED"),
        (PolicyDecision.REQUIRE_APPROVAL, "UNRELATED_APPROVAL_REJECTED"),
    ]
    assert observe_strategy_gates(strategy, (ToolPermission.NETWORK_READ,)) == evidence


def test_v3_alignment_old_unknowns_and_unobservable_measurements_preserved():
    source, facts, spec, plan, baseline, truths = inputs()
    legacy = execute_pair(source, spec, plan, facts, baseline, truths)
    current = execute_pair(
        source,
        facts=facts,
        specification=spec,
        plan=plan,
        baseline=baseline,
        ground_truth=truths,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    assert current.candidate_result.content.strategy_safety.strategy == compile_candidate_strategy(
        source
    )
    assert current.variant == legacy.variant or current.variant.content == legacy.variant.content
    assert current.baseline_result.content.cases == current.candidate_result.content.cases
    assert current.baseline_result.content.cases == legacy.baseline_result.content.cases
    assert current.comparison.comparison_id != legacy.comparison.comparison_id
    delta = next(
        m for m in current.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
    )
    assert delta.baseline.value == len(current.baseline_result.content.cases)
    assert delta.candidate.value == 0 and delta.delta == -delta.baseline.value
    for invariant in (HardInvariant.NO_POLICY_BYPASS, HardInvariant.NO_APPROVAL_BYPASS):
        assert (
            next(i for i in legacy.comparison.content.safety if i.invariant == invariant).candidate
            == VerdictState.UNKNOWN
        )
        assert (
            next(i for i in current.comparison.content.safety if i.invariant == invariant).candidate
            == VerdictState.PASS
        )
    assert all(
        s.candidate == s.baseline == VerdictState.PASS for s in current.comparison.content.safety
    )
    unknown = next(
        m for m in current.comparison.content.metrics if m.metric == MetricName.UNNECESSARY_PATHS
    )
    assert unknown.candidate.state == ValueState.NOT_MEASURABLE and unknown.candidate.value is None
    assert any(c.status == VerdictState.UNKNOWN for c in current.comparison.content.acceptance)
    assert (
        "LOCAL_GATE_PROBES_NOT_PRODUCTION_LLM_REPLAY" in current.candidate_result.content.blockers
    )
    with pytest.raises(StoredDataError, match="apples-to-apples"):
        compare(spec, legacy.baseline_result, current.candidate_result)
    replay = execute_pair(
        source,
        spec,
        plan,
        tuple(reversed(facts)),
        baseline,
        truths,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    assert replay.comparison.comparison_id == current.comparison.comparison_id


def test_observed_gate_failure_cannot_be_masked_by_coverage_improvement(monkeypatch):
    monkeypatch.setattr(GovernedExecutor, "preflight", lambda *args, **kwargs: None)
    source, facts, spec, plan, baseline, truths = inputs()
    result = execute_pair(
        source,
        spec,
        plan,
        facts,
        baseline,
        truths,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    assert result.candidate_result.content.strategy_safety.policy_status == "FAIL"
    assert result.candidate_result.content.strategy_safety.approval_status == "FAIL"
    assert any(m.outcome == "IMPROVED" for m in result.comparison.content.metrics)
    assert (
        next(
            c
            for c in result.comparison.content.acceptance
            if c.metric == MetricName.GOVERNANCE_VIOLATIONS
        ).status
        == VerdictState.FAIL
    )


def test_historical_ground_truth_unknown_is_not_replaced_by_sandbox_fixtures():
    from soc_agent.offline_comparison.coverage_models import CoverageGroundTruth

    source, facts, spec, plan, baseline, truths = inputs()
    truths[next(iter(truths))] = CoverageGroundTruth(
        status="NOT_MEASURABLE", required_permissions=(), feedback_refs=()
    )
    result = execute_pair(
        source,
        spec,
        plan,
        facts,
        baseline,
        truths,
        evaluator_version=CONTRACT_EVALUATOR_VERSION,
    )
    missing = next(
        m for m in result.comparison.content.metrics if m.metric == MetricName.MISSED_PATHS
    )
    assert missing.outcome == "NOT_MEASURABLE" and missing.delta is None
    assert (
        next(
            c for c in result.comparison.content.acceptance if c.metric == MetricName.MISSED_PATHS
        ).status
        == VerdictState.UNKNOWN
    )


@pytest.mark.asyncio
async def test_preflight_success_never_authorizes_later_execution(monkeypatch):
    from uuid import UUID

    mock = MockTool(
        metadata=ToolMetadata(
            name="local_read_probe",
            description="Local negative execution probe",
            permission=ToolPermission.NETWORK_READ,
            risk_level=ToolRiskLevel.READ_ONLY,
        ),
        input_model=ProbePayload,
        output_model=ProbePayload,
        responses=[{}],
    )
    registry = ToolRegistry()
    registry.register(mock.tool)
    policy = PolicyEngine()
    executor = GovernedExecutor(registry=registry, policy=policy, approvals=ApprovalManager())
    action = ActionProposal(incident_id=UUID(int=1), tool_name="local_read_probe", tool_input="{}")
    assert executor.preflight(action) == mock.tool.metadata
    monkeypatch.setattr(
        policy,
        "evaluate",
        lambda metadata: PolicyResult(decision=PolicyDecision.DENY, reason="Local denial"),
    )
    with pytest.raises(ExecutionDeniedError):
        await executor.execute(action)
    assert mock.call_count == 0
