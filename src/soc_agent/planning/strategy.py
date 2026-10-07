"""Declarative read-only planning constraints; never execution authorization."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from soc_agent.investigation.models import InvestigationPlan
from soc_agent.planning.errors import PlanningError
from soc_agent.state import IncidentState
from soc_agent.tools import Tool, ToolMetadata
from soc_agent.tools.models import ReadOnlyPermission

STRATEGY_VERSION = "soc-investigation-strategy:v1"


class InvestigationStrategy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    strategy_version: Literal["soc-investigation-strategy:v1"] = STRATEGY_VERSION
    strategy_type: Literal["INVESTIGATION_STRATEGY"] = "INVESTIGATION_STRATEGY"
    operation: Literal["REQUIRE_READ_ONLY_PERMISSION_COVERAGE"] = (
        "REQUIRE_READ_ONLY_PERMISSION_COVERAGE"
    )
    required_permissions: tuple[ReadOnlyPermission, ...] = Field(min_length=1, max_length=3)

    @field_validator("required_permissions", mode="after")
    @classmethod
    def canonical(cls, value: tuple[ReadOnlyPermission, ...]) -> tuple[ReadOnlyPermission, ...]:
        return tuple(sorted(set(value)))


class UnsatisfiableStrategy(PlanningError):
    """No registered read-only capability can satisfy the constraint."""


class StrategyCoverageError(PlanningError):
    """The single validated planner output does not satisfy the constraint."""


class InvestigationStrategyProvider(Protocol):
    def get_strategy(self, context: IncidentState) -> InvestigationStrategy | None: ...


@dataclass(frozen=True)
class ExplicitStrategyProvider:
    strategy: InvestigationStrategy | None = None

    def get_strategy(self, context: IncidentState) -> InvestigationStrategy | None:
        return (
            InvestigationStrategy.model_validate(self.strategy.model_dump())
            if self.strategy is not None
            else None
        )


def missing_coverage(
    strategy: InvestigationStrategy, metadata: tuple[ToolMetadata, ...]
) -> tuple[ReadOnlyPermission, ...]:
    """Shared set semantics, based only on validated capability declarations."""
    strategy = InvestigationStrategy.model_validate(strategy.model_dump())
    checked = tuple(ToolMetadata.model_validate(m.model_dump()) for m in metadata)
    covered = {m.permission for m in checked if m.is_read_only_capability}
    return missing_permissions(strategy, tuple(covered))


def missing_permissions(
    strategy: InvestigationStrategy, covered: tuple[ReadOnlyPermission, ...]
) -> tuple[ReadOnlyPermission, ...]:
    """One coverage relation for historical facts and registry-validated plans."""
    strategy = InvestigationStrategy.model_validate(strategy.model_dump())
    return tuple(p for p in strategy.required_permissions if p not in covered)


def ensure_satisfiable(
    strategy: InvestigationStrategy, tools: Mapping[str, Tool[BaseModel, BaseModel]]
) -> None:
    if missing_coverage(strategy, tuple(t.metadata for t in tools.values())):
        raise UnsatisfiableStrategy("Required read-only capability is absent from planning catalog")


def validate_strategy(
    plan: InvestigationPlan,
    strategy: InvestigationStrategy,
    *,
    tools: Mapping[str, Tool[BaseModel, BaseModel]],
) -> InvestigationPlan:
    """Validate coverage without altering steps, inputs, permissions, or state."""
    from soc_agent.planning.errors import InvalidPlannedToolInputError, UnknownPlannedToolError

    plan = InvestigationPlan.model_validate(plan.model_dump())
    ensure_satisfiable(strategy, tools)
    metadata = []
    for step in plan.steps:
        if step.tool_name not in tools:
            raise UnknownPlannedToolError("Strategy validation requires a registered tool")
        tool = tools[step.tool_name]
        try:
            tool.input_model.model_validate_json(step.tool_input, extra="forbid")
        except ValueError as error:
            raise InvalidPlannedToolInputError(
                "Strategy cannot override input validation"
            ) from error
        metadata.append(tool.metadata)
    if missing_coverage(strategy, tuple(metadata)):
        raise StrategyCoverageError("Validated plan is missing required read-only coverage")
    return plan
