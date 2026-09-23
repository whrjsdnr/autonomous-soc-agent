"""Real saved package inference; only assessment LLM mocked.

Human confirmations use an explicit test-only external authentication boundary.
The SQLite store performs durable applications and replay checks.
External human authentication is simulated by a test-only adapter.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.review_support import HumanConfirmations, authorize, record_review
from tests.scenarios.test_security_ai_fusion import PINS, fuse, inputs_for, network_features
from tests.unit.execution.conftest import make_tool

from soc_agent.approval import ApprovalManager, ApprovalNotFoundError
from soc_agent.assessment import ThreatAssessor
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.llm import MockLLMClient
from soc_agent.policy import PolicyEngine
from soc_agent.review import (
    AuthorizationAlreadyApplied,
    ReviewError,
    ReviewOutcome,
    SeverityChange,
    StaleSnapshotError,
    StatusChange,
)
from soc_agent.review.models import ApplicationResult
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.security_ai.packaging import load_package
from soc_agent.state import Evidence, IncidentState
from soc_agent.tools import ToolPermission, ToolRegistry, ToolRiskLevel


@pytest.fixture(scope="module")
def packages():
    root = Path(__file__).parents[1] / "fixtures/security_ai_packages"
    return {name: load_package(root / name, expected_manifest_digest=pin) for name, pin, _ in PINS}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "review_only",
        "investigate",
        "severity",
        "status",
        "stale",
        "cross_incident",
        "replay",
        "tool_mix",
        "failure",
    ],
)
async def test_packaged_models_through_persistent_application(
    packages, case, monkeypatch, tmp_path
):
    state = IncidentState()
    evidence = Evidence(
        incident_id=state.incident_id,
        source="synthetic log",
        summary="Synthetic telemetry for review",
        raw_data="{}",
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    state = state.add_evidence(evidence)
    features = network_features()
    signals = await inputs_for(
        packages, state, {"network_classifier": features, "network_anomaly": features}
    )
    fusion = fuse(packages, state, signals)
    assert {c.decision for c in fusion.contributions} == {"BruteForce", "anomaly"}
    llm = MockLLMClient(
        [
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "high",
                    "confidence": 0.2,
                    "summary": "Unverified model concern, no established attack success.",
                    "supporting_evidence_ids": [str(evidence.evidence_id)],
                },
            }
        ]
    )
    assessment = await ThreatAssessor(llm_client=llm).assess(state, fusion_result=fusion)
    decision = IncidentDecisionEngine().decide(
        state, assessment.threat_assessment, fusion_assessment=assessment
    )
    before = state.model_dump_json(), decision.model_dump_json(), fusion.model_dump_json()

    def forbidden_analysis(*args, **kwargs):
        pytest.fail("Review/application attempted new inference or decision generation")

    from soc_agent.security_ai.fusion import MultiModelFusionEngine
    from soc_agent.security_ai.packaging.package import ModelPackage

    for cls, name in (
        (IncidentDecisionEngine, "decide"),
        (ThreatAssessor, "assess"),
        (ModelPackage, "predict"),
        (MultiModelFusionEngine, "fuse"),
    ):
        monkeypatch.setattr(cls, name, forbidden_analysis)
    authority = HumanConfirmations()
    other_state = IncidentState()
    store = SQLiteGovernanceStore.create(tmp_path / "scenario.sqlite")
    store.register(state)
    store.register(other_state)
    service = PersistentHumanReviewService(store=store, authority=authority)
    review_request = service.request_review(state, decision)
    outcome = {
        "review_only": ReviewOutcome.ACKNOWLEDGED,
        "investigate": ReviewOutcome.INVESTIGATE,
    }.get(case, ReviewOutcome.CHANGE_ELIGIBLE)
    review = record_review(service, authority, review_request, outcome)
    assert service.authorizations() == store.applications() == ()
    if case in ("review_only", "investigate"):
        with pytest.raises(ReviewError):
            service.propose_change(
                review,
                changes=(SeverityChange(before="info", after="high"),),
                reason="Not authorized by review",
            )
        assert store.load(state.incident_id).state == state
    else:
        changes = (
            (StatusChange(before="new", after="triaging"),)
            if case == "status"
            else (SeverityChange(before="info", after="medium"),)
        )
        request = service.propose_change(
            review, changes=changes, reason="Human selected exactly these changes"
        )
        authorization = authorize(service, authority, request, review)
        assert store.load(state.incident_id).state == state
        assert store.applications() == ()
        if case == "stale":
            later = store.append_evidence(
                request.target.snapshot,
                Evidence(
                    incident_id=state.incident_id,
                    source="later",
                    summary="Later evidence",
                    raw_data="{}",
                    observed_at=evidence.observed_at,
                ),
            )
            with pytest.raises(StaleSnapshotError):
                service.apply(state, decision, review, request, authorization)
            assert store.load(state.incident_id) == later
        elif case == "cross_incident":
            with pytest.raises(ReviewError):
                service.apply(other_state, decision, review, request, authorization)
            assert store.load(other_state.incident_id).state == other_state
            assert store.load(state.incident_id).state == state
        elif case == "tool_mix":
            registry, approvals = ToolRegistry(), ApprovalManager()
            tool = make_tool(ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH)
            registry.register(tool.tool)
            executor = GovernedExecutor(
                registry=registry, policy=PolicyEngine(), approvals=approvals
            )
            action = ActionProposal(
                incident_id=state.incident_id,
                tool_name=tool.tool.metadata.name,
                tool_input={"target": "host_a"},
            )
            tool_request = executor.request_approval(action, reason="Tool request only")
            tool_approval = approvals.approve(tool_request.approval_id, actor="test human")
            with pytest.raises(ReviewError):
                service.apply(state, decision, review, request, tool_approval)
            with pytest.raises(ApprovalNotFoundError):
                await executor.execute(action, approval_id=authorization.authorization_id)
            assert tool.call_count == 0
            assert store.load(state.incident_id).state == state
        elif case == "failure":

            def fail(*args, **kwargs):
                raise RuntimeError("Injected pre-commit storage validation failure")

            with monkeypatch.context() as guard:
                guard.setattr(ApplicationResult, "model_validate", fail)
                with pytest.raises(RuntimeError, match="pre-commit"):
                    service.apply(state, decision, review, request, authorization)
            assert store.load(state.incident_id).state == state
            assert store.applications() == ()
            assert store.events()[-1].failure_type == "RuntimeError"
        else:
            result = service.apply(state, decision, review, request, authorization)
            assert store.applications() == (result,)
            assert result.audit.target == review.target
            assert result.audit.review_id == review.review_id
            assert result.audit.authorization_id == authorization.authorization_id
            assert result.incident_state.evidence == state.evidence
            assert result.incident_state.confidence == state.confidence
            assert result.incident_state.severity == ("info" if case == "status" else "medium")
            assert result.incident_state.status == ("triaging" if case == "status" else "new")
            reopened = SQLiteGovernanceStore(store.database.path)
            assert reopened.load(state.incident_id).state == result.incident_state
            assert reopened.applications() == (result,)
            assert reopened.events() == store.events()
            assert reopened.authorization_status(authorization.authorization_id).consumed
            service = PersistentHumanReviewService(store=reopened)
            if case == "replay":
                with pytest.raises(AuthorizationAlreadyApplied):
                    service.apply(state, decision, review, request, authorization)
                assert len(store.applications()) == 1
        if case in ("stale", "cross_incident", "tool_mix", "failure"):
            assert store.applications() == ()
            assert store.events()[-1].request_id == request.request_id
    assert (state.model_dump_json(), decision.model_dump_json(), fusion.model_dump_json()) == before
    assert decision.model_derived_context == fusion
    assert fusion.confidence_state == "unknown"
    assert llm.call_count == 1
