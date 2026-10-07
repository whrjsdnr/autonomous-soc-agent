"""Deterministic local gate probes; no Tool dispatch or production capabilities."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.approval import ApprovalManager
from soc_agent.approval.errors import ApprovalNotFoundError
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ApprovalRequiredError, ExecutionDeniedError
from soc_agent.planning.models import LLMInvestigationPlanDraft, LLMInvestigationStepDraft
from soc_agent.planning.strategy import InvestigationStrategy, validate_strategy
from soc_agent.planning.validator import normalize_plan
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.review.models import Frozen
from soc_agent.tools import Tool, ToolMetadata, ToolPermission, ToolRegistry, ToolRiskLevel
from soc_agent.tools.models import ReadOnlyPermission

SAFETY_VERSION = "soc-investigation-strategy-gate-probes:v1"


class ProbeObservation(Frozen):
    metadata: ToolMetadata
    policy_decision: PolicyDecision
    boundary_outcome: Literal[
        "ALLOWED", "POLICY_DENIED", "APPROVAL_REQUIRED", "UNRELATED_APPROVAL_REJECTED"
    ]
    supplied_unregistered_approval: bool = False


class StrategySafetyEvidence(Frozen):
    safety_version: Literal["soc-investigation-strategy-gate-probes:v1"] = SAFETY_VERSION
    fixture_scope: Literal["FIXED_LOCAL_CATALOG_NOT_PRODUCTION_PLANNER_REPLAY"] = (
        "FIXED_LOCAL_CATALOG_NOT_PRODUCTION_PLANNER_REPLAY"
    )
    strategy: InvestigationStrategy | None
    selected_permissions: tuple[ReadOnlyPermission, ...]
    plan_validation: Literal["PASS", "NOT_APPLICABLE"]
    observations: tuple[ProbeObservation, ...]
    policy_status: Literal["PASS", "FAIL", "UNKNOWN"]
    approval_status: Literal["PASS", "FAIL", "UNKNOWN"]
    approvals_created: int = Field(ge=0, strict=True)
    tool_calls: Literal[0] = 0


class ProbePayload(Frozen):
    """An explicitly empty fixture schema, never historical tool input."""


async def _forbidden_handler(payload: ProbePayload) -> object:
    raise AssertionError("Gate probes cannot dispatch Tools")


def observe_strategy_gates(
    strategy: InvestigationStrategy | None,
    selected_permissions: tuple[ReadOnlyPermission, ...],
) -> StrategySafetyEvidence:
    """Validate a local sandbox plan, then observe real policy/executor gate results.

    Fixed fixture Tool names exist only in this local registry. They do not fill
    missing production capabilities or reproduce historical tool inputs.
    """
    if strategy is not None:
        strategy = InvestigationStrategy.model_validate(strategy.model_dump())
    registry = ToolRegistry()
    for permission in (
        ToolPermission.FILE_READ,
        ToolPermission.NETWORK_READ,
        ToolPermission.SYSTEM_READ,
    ):
        registry.register(
            Tool(
                ToolMetadata(
                    name=f"sandbox_{permission.value}",
                    description="Local gate probe only",
                    permission=permission,
                    risk_level=ToolRiskLevel.READ_ONLY,
                ),
                ProbePayload,
                ProbePayload,
                _forbidden_handler,
            )
        )
    for name, risk in (
        ("sandbox_denied_write", ToolRiskLevel.DESTRUCTIVE),
        ("sandbox_governed_write", ToolRiskLevel.LOW),
    ):
        registry.register(
            Tool(
                ToolMetadata(
                    name=name,
                    description="Negative gate probe only",
                    permission=ToolPermission.NETWORK_WRITE,
                    risk_level=risk,
                ),
                ProbePayload,
                ProbePayload,
                _forbidden_handler,
            )
        )
    tools = {m.name: registry.get(m.name) for m in registry.list()}
    read_names = tuple(f"sandbox_{p.value}" for p in selected_permissions)
    if read_names:
        draft = LLMInvestigationPlanDraft(
            goal="Validate explicit local fixture coverage",
            steps=tuple(
                LLMInvestigationStepDraft(tool_name=name, tool_input={}, purpose="Gate probe")
                for name in read_names
            ),
        )
        plan = normalize_plan(draft, incident_id=UUID(int=1), tools=tools)
        if strategy is not None:
            validate_strategy(plan, strategy, tools=tools)
    elif strategy is not None:
        raise ValueError("A strategy cannot be validated against an empty sandbox plan")
    policy, approvals = PolicyEngine(), ApprovalManager()
    executor = GovernedExecutor(registry=registry, policy=policy, approvals=approvals)
    observations = []
    for index, (name, unrelated_approval) in enumerate(
        (
            *((name, False) for name in read_names),
            ("sandbox_denied_write", False),
            ("sandbox_governed_write", False),
            ("sandbox_governed_write", True),
        ),
        start=1,
    ):
        metadata = registry.get(name).metadata
        decision = policy.evaluate(metadata).decision
        action = ActionProposal(
            action_id=UUID(int=index),
            incident_id=UUID(int=1),
            tool_name=name,
            tool_input="{}",
            created_at=datetime(2000, 1, 1, tzinfo=UTC),
        )
        try:
            executor.preflight(action, approval_id=UUID(int=100) if unrelated_approval else None)
            outcome = "ALLOWED"
        except ExecutionDeniedError:
            outcome = "POLICY_DENIED"
        except ApprovalRequiredError:
            outcome = "APPROVAL_REQUIRED"
        except ApprovalNotFoundError:
            outcome = "UNRELATED_APPROVAL_REJECTED"
        observations.append(
            ProbeObservation(
                metadata=metadata,
                policy_decision=decision,
                boundary_outcome=outcome,
                supplied_unregistered_approval=unrelated_approval,
            )
        )
    denied, governed, unrelated = observations[-3:]
    policy_pass = (
        denied.policy_decision == PolicyDecision.DENY
        and denied.boundary_outcome == "POLICY_DENIED"
        and governed.policy_decision == PolicyDecision.REQUIRE_APPROVAL
        and all(
            o.policy_decision == PolicyDecision.ALLOW and o.boundary_outcome == "ALLOWED"
            for o in observations[:-3]
        )
    )
    approval_pass = (
        governed.boundary_outcome == "APPROVAL_REQUIRED"
        and unrelated.boundary_outcome == "UNRELATED_APPROVAL_REJECTED"
        and not approvals.list()
    )
    return StrategySafetyEvidence(
        strategy=strategy,
        selected_permissions=selected_permissions,
        plan_validation="PASS" if read_names else "NOT_APPLICABLE",
        observations=tuple(observations),
        policy_status="PASS" if policy_pass else "FAIL",
        approval_status="PASS" if approval_pass else "FAIL",
        approvals_created=len(approvals.list()),
    )
