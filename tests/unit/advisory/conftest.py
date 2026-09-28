import pytest
from tests.review_support import record_review
from tests.unit.execution.conftest import make_tool
from tests.unit.persistence.conftest import case as case

from soc_agent.response.advisory import CandidateIntent, PersistentPlanningSource, ResponsePlanner
from soc_agent.tools import ToolPermission, ToolRegistry, ToolRiskLevel


@pytest.fixture
def planning(case):
    state, decision, authority, store, service = case
    review = record_review(service, authority, service.request_review(state, decision))
    registry = ToolRegistry()
    for permission, risk, name in (
        (ToolPermission.NETWORK_READ, ToolRiskLevel.READ_ONLY, "inspect_logs"),
        (ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH, "test_response"),
        (ToolPermission.SYSTEM_WRITE, ToolRiskLevel.DESTRUCTIVE, "test_destructive"),
    ):
        registry.register(make_tool(permission, risk, name).tool)
    planner = ResponsePlanner(registry=registry, source=PersistentPlanningSource(store))
    candidate = CandidateIntent(
        candidate_tool="inspect_logs",
        proposed_input={"target": "host_a"},
        purpose="Inspect relevant records",
        rationale="Verify source concern",
        evidence_ids=(state.evidence[0].evidence_id,),
    )
    return state, decision, review, store, service, registry, planner, candidate, authority


def create(planning, candidates=None, **updates):
    state, decision, review, _, _, _, planner, candidate, _ = planning
    data = dict(
        incident_state=state,
        decision=decision,
        review=review,
        objective="Consider bounded responses",
        candidates=(candidate,) if candidates is None else candidates,
    )
    data.update(updates)
    return planner.create_plan(**data)
