"""Real governance/execution components with deterministic LLM and Tool adapters."""

from types import SimpleNamespace

import pytest
from tests.review_support import HumanConfirmations, record_review
from tests.unit.execution.conftest import SampleInput, SampleOutput
from tests.unit.promotion.conftest import CurrentPolicy, approve, promoted

from soc_agent._json import canonical_json_object
from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable import DurableExecutor, ExecutionStore, migrate
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.investigation.runtime import SOCRuntime, WorkflowStep
from soc_agent.llm import MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.response.advisory import CandidateIntent, PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.review import ReviewOutcome
from soc_agent.review.persistence import PersistentHumanReviewService, SQLiteGovernanceStore
from soc_agent.state import Evidence, IncidentState
from soc_agent.state.evidence import utc_now
from soc_agent.tools import MockTool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel


class AnalysisLLM:
    def __init__(self, store, incident_id, severities):
        self.store, self.incident_id = store, incident_id
        self.severities = iter(severities)
        self.calls = 0

    async def generate_structured(self, *, request, response_model):
        self.calls += 1
        state = self.store.load(self.incident_id).state
        ids = [str(state.evidence[-1].evidence_id)]
        return response_model.model_validate(
            {
                "observations": [
                    {
                        "ref": "O1",
                        "statement": "Source contains a test record",
                        "supporting_evidence_ids": ids,
                    }
                ],
                "hypotheses": [],
                "assessment": {
                    "severity": next(self.severities),
                    "confidence": 0.8,
                    "summary": "Synthetic advisory analysis",
                    "supporting_evidence_ids": ids,
                    "supporting_observation_refs": ["O1"],
                },
            }
        )


@pytest.fixture
def runtime_case(tmp_path):
    count = 0

    def build(
        *,
        evidence=True,
        severities=("info",),
        plans=("host_a", "host_b"),
        responses=None,
        limit=2,
        model_analysis=None,
        event_fields=None,
    ):
        nonlocal count
        count += 1
        state = IncidentState()
        if evidence:
            state = state.add_evidence(
                Evidence(
                    incident_id=state.incident_id,
                    source="fixture",
                    summary="Test input",
                    raw_data=canonical_json_object(event_fields or {}),
                    observed_at=utc_now(),
                )
            )
        store = SQLiteGovernanceStore.create(tmp_path / f"runtime-{count}.sqlite")
        store.register(state)
        migrate(store.database)
        authority, policy, registry = HumanConfirmations(), CurrentPolicy(), ToolRegistry()
        mocks = {}
        for name, permission, risk in (
            ("inspect_logs", ToolPermission.NETWORK_READ, ToolRiskLevel.READ_ONLY),
            ("test_response", ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH),
        ):
            mock = MockTool(
                metadata=ToolMetadata(
                    name=name, description="Test adapter", permission=permission, risk_level=risk
                ),
                input_model=SampleInput,
                output_model=SampleOutput,
                responses=responses if responses is not None else [{"result": "ok"}] * 8,
            )
            registry.register(mock.tool)
            mocks[name] = mock
        approvals = ApprovalManager()
        promotion_service = PromotionService(
            store=store, registry=registry, policy=policy, authority=authority
        )
        bridge = ExecutionBridge(
            promotions=promotion_service, approvals=approvals, authority=authority
        )
        investigation = InvestigationOrchestrator(
            executor=GovernedExecutor(registry=registry, policy=policy, approvals=approvals)
        )
        planner_llm = MockLLMClient(
            [
                {
                    "goal": "Collect source context",
                    "steps": [
                        {
                            "tool_name": "inspect_logs",
                            "tool_input": {"target": target},
                            "purpose": "Read source records",
                        }
                    ],
                }
                for target in plans
            ]
        )
        llm = AnalysisLLM(store, state.incident_id, severities)
        response_planner = ResponsePlanner(
            registry=registry, source=PersistentPlanningSource(store)
        )
        executor = DurableExecutor(store=ExecutionStore(store), registry=registry, policy=policy)
        runtime = SOCRuntime(
            investigator=investigation,
            store=store,
            planner=InvestigationPlanner(llm_client=planner_llm, registry=registry),
            assessor=ThreatAssessor(llm_client=llm),
            responses=response_planner,
            bridge=bridge,
            executor=executor,
            max_investigation_rounds=limit,
            model_analysis=model_analysis,
        )
        runtime.start(state.incident_id)
        return SimpleNamespace(
            runtime=runtime,
            incident_id=state.incident_id,
            initial=state,
            store=store,
            authority=authority,
            policy=policy,
            mocks=mocks,
            llm=llm,
            planner_llm=planner_llm,
            executor=executor,
            bridge=bridge,
            approvals=approvals,
            promotion_service=promotion_service,
            reviews=PersistentHumanReviewService(store=store, authority=authority),
        )

    return build


async def decision_ready(case):
    # Bounded test driver: runtime itself never contains an automatic runner.
    for _ in range(10):
        result = await case.runtime.advance(case.incident_id)
        if result.current_step == WorkflowStep.DECIDE:
            return result
    raise AssertionError("Decision was not reached")


def review_for(case, outcome=ReviewOutcome.CHANGE_ELIGIBLE):
    state = case.store.load(case.incident_id).state
    decision = case.runtime.artifacts(case.incident_id).decision
    return record_review(
        case.reviews, case.authority, case.reviews.request_review(state, decision), outcome=outcome
    )


async def promoted_ready(case, *, write=False, approval=True):
    await decision_ready(case)
    result = await case.runtime.advance(case.incident_id, review=review_for(case))
    assert result.next_step == WorkflowStep.GOVERN
    state = case.store.load(case.incident_id).state
    tool = "test_response" if write else "inspect_logs"
    candidate = CandidateIntent(
        candidate_tool=tool,
        proposed_input={"target": "host_a"},
        purpose="Human-selected response",
        rationale="Consider source findings",
        evidence_ids=(state.evidence[0].evidence_id,),
    )
    await case.runtime.advance(case.incident_id, candidates=(candidate,))
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
    value = promoted(workflow, tool)
    approved = approve(workflow, value).approval_id if write and approval else None
    result = await case.runtime.advance(case.incident_id, promoted=value, approval_id=approved)
    return value, workflow, result
