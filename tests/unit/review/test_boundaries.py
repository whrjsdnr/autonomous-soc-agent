import pytest
from tests.review_support import authorize, record_review
from tests.unit.execution.conftest import make_tool

from soc_agent.approval import ApprovalManager, ApprovalNotFoundError
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.policy import PolicyEngine
from soc_agent.review import ReviewError
from soc_agent.tools import ToolPermission, ToolRegistry, ToolRiskLevel


@pytest.mark.asyncio
async def test_tool_and_state_authorizations_cannot_mix(prepared):
    state, decision, _, store, service, review, request, authorization = prepared
    registry, approvals = ToolRegistry(), ApprovalManager()
    tool = make_tool(ToolPermission.NETWORK_WRITE, ToolRiskLevel.HIGH)
    registry.register(tool.tool)
    executor = GovernedExecutor(registry=registry, approvals=approvals, policy=PolicyEngine())
    action = ActionProposal(
        incident_id=state.incident_id,
        tool_name=tool.tool.metadata.name,
        tool_input={"target": "host_a"},
    )
    tool_request = executor.request_approval(action, reason="Tool-only authorization")
    approved_tool = approvals.approve(tool_request.approval_id, actor="human")
    before = approvals.list(), executor._attempted.copy()
    with pytest.raises(ReviewError, match="StateChangeAuthorization"):
        service.apply(state, decision, review, request, approved_tool)
    with pytest.raises(ApprovalNotFoundError):
        await executor.execute(action, approval_id=authorization.authorization_id)
    assert tool.call_count == 0
    assert (approvals.list(), executor._attempted) == before
    assert store.load(state.incident_id).state == state
    assert store.applications() == ()
    assert service.failures()[-1].outcome == "failed"
    assert service.failures()[-1].registered_request == request
    assert service.failures()[-1].authorization_id is None


def test_governance_services_never_called(case, monkeypatch):
    from soc_agent.decision import IncidentDecisionEngine
    from soc_agent.llm import MockLLMClient
    from soc_agent.review import SeverityChange
    from soc_agent.security_ai import SecurityAI, SecurityAIRegistry
    from soc_agent.security_ai.fusion import MultiModelFusionEngine
    from soc_agent.security_ai.packaging.package import ModelPackage
    from soc_agent.tools import Tool

    state, decision, authority, store, service = case
    approvals, policy, registry = ApprovalManager(), PolicyEngine(), SecurityAIRegistry()
    before = (
        state.model_dump_json(),
        decision.model_dump_json(),
        approvals.list(),
        vars(policy).copy(),
        registry.list(),
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Human review crossed a model, execution or governance boundary")

    for cls, name in (
        (IncidentDecisionEngine, "decide"),
        (MockLLMClient, "generate_structured"),
        (SecurityAI, "predict"),
        (ModelPackage, "predict"),
        (MultiModelFusionEngine, "fuse"),
        (Tool, "execute"),
        (GovernedExecutor, "execute"),
        (GovernedExecutor, "request_approval"),
        (ApprovalManager, "create"),
        (ApprovalManager, "approve"),
        (ApprovalManager, "reject"),
        (PolicyEngine, "evaluate"),
        (ToolRegistry, "register"),
        (SecurityAIRegistry, "register"),
    ):
        monkeypatch.setattr(cls, name, forbidden)
    review = record_review(service, authority, service.request_review(state, decision))
    request = service.propose_change(
        review,
        changes=(SeverityChange(before="info", after="high"),),
        reason="Explicit human choice",
    )
    authorization = authorize(service, authority, request, review)
    service.apply(state, decision, review, request, authorization)
    assert (
        state.model_dump_json(),
        decision.model_dump_json(),
        approvals.list(),
        vars(policy),
        registry.list(),
    ) == before


def test_failure_audit_has_no_partial_state(prepared, monkeypatch):
    from soc_agent.review.models import ApplicationAudit

    state, decision, _, store, service, review, request, authorization = prepared

    def fail(*args, **kwargs):
        raise RuntimeError("Simulated construction failure after new state was built")

    monkeypatch.setattr(ApplicationAudit, "__init__", fail)
    with pytest.raises(RuntimeError, match="construction failure"):
        service.apply(state, decision, review, request, authorization)
    failure = service.failures()[-1]
    assert failure.registered_request.target.incident_id == state.incident_id
    assert failure.registered_request.review_id == review.review_id
    assert failure.authorization_id == authorization.authorization_id
    assert failure.error_type == "RuntimeError"
    assert failure.outcome == "failed"
    assert "incident_state" not in type(failure).model_fields
    assert store.applications() == ()
    assert store.load(state.incident_id).state == state
