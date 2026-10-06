"""Narrow permission-coverage contracts; no tool names, code or runtime authority."""

from typing import Literal, Self

from pydantic import Field, model_validator

from soc_agent.improvement_dataset.models import ArtifactReference
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen, Hash
from soc_agent.state.evidence import UTCTimestamp, utc_now
from soc_agent.tools.enums import ToolPermission
from soc_agent.tools.models import ReadOnlyPermission

ADAPTER_VERSION = "soc-offline-permission-coverage-adapter:v1"
TARGET_REFERENCE = "soc_agent.planning.models.PlannerInput"
READ_ONLY = (ToolPermission.FILE_READ, ToolPermission.NETWORK_READ, ToolPermission.SYSTEM_READ)


class CoverageConfiguration(Frozen):
    """Caller-supplied offline paths, not a capture of production planner behavior."""

    covered_permissions: tuple[ReadOnlyPermission, ...] = ()

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if self.covered_permissions != tuple(sorted(set(self.covered_permissions))):
            raise ValueError("Canonical unique read-only coverage required")
        return self


class BaselineContent(Frozen):
    schema_version: Literal["frozen-offline-baseline:v1"] = "frozen-offline-baseline:v1"
    target_component: Literal["investigation_planning"] = "investigation_planning"
    target_reference: Literal["soc_agent.planning.models.PlannerInput"] = TARGET_REFERENCE
    configuration: CoverageConfiguration
    adapter_version: Literal["soc-offline-permission-coverage-adapter:v1"] = ADAPTER_VERSION
    source_reference: Literal["soc_agent.tools.models.ToolMetadata.is_read_only_capability"] = (
        "soc_agent.tools.models.ToolMetadata.is_read_only_capability"
    )
    permission_contract: tuple[ReadOnlyPermission, ...] = READ_ONLY
    provenance: Literal["EXPLICIT_OFFLINE_CONFIGURATION_NOT_HISTORICAL"] = (
        "EXPLICIT_OFFLINE_CONFIGURATION_NOT_HISTORICAL"
    )
    authority: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"

    @model_validator(mode="after")
    def contract(self) -> Self:
        if self.permission_contract != READ_ONLY:
            raise ValueError("Frozen baseline must bind the exact read-only contract")
        return self


class FrozenBaseline(Frozen):
    baseline_id: Hash
    baseline_version: Hash
    content: BaselineContent
    created_at: UTCTimestamp = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def identity(self) -> Self:
        if not self.baseline_id == self.baseline_version == content_digest(self.content):
            raise ValueError("Frozen baseline identity mismatch")
        return self


class CoverageGroundTruth(Frozen):
    status: Literal["MEASURABLE", "NOT_MEASURABLE"]
    required_permissions: tuple[ReadOnlyPermission, ...]
    feedback_refs: tuple[ArtifactReference, ...]

    @model_validator(mode="after")
    def support(self) -> Self:
        if self.required_permissions != tuple(sorted(set(self.required_permissions))) or (
            tuple(r.identity for r in self.feedback_refs)
            != tuple(sorted({r.identity for r in self.feedback_refs}))
        ):
            raise ValueError("Canonical ground truth required")
        if (self.status == "MEASURABLE") != bool(self.required_permissions and self.feedback_refs):
            raise ValueError("Measurable coverage requires explicit human facts and provenance")
        if self.status == "NOT_MEASURABLE" and (self.required_permissions or self.feedback_refs):
            raise ValueError("Unknown ground truth cannot carry inferred requirements")
        return self


class CoverageOutput(Frozen):
    """Frozen output schema for the pure adapter's selected paths."""

    selected_permissions: tuple[ReadOnlyPermission, ...]


class CoverageTrace(Frozen):
    adapter_version: Literal["soc-offline-permission-coverage-adapter:v1"] = ADAPTER_VERSION
    configuration_digest: Hash
    # An observation schema can also retain violating selections for safety diagnosis.
    selected_permissions: tuple[ToolPermission, ...]
    required_permissions: tuple[ReadOnlyPermission, ...] | None
    missing_permissions: tuple[ReadOnlyPermission, ...] | None

    @model_validator(mode="after")
    def observation(self) -> Self:
        if self.selected_permissions != tuple(sorted(set(self.selected_permissions))):
            raise ValueError("Canonical observed selection required")
        if self.required_permissions is None:
            if self.missing_permissions is not None:
                raise ValueError("Unknown requirements cannot imply a missing-path count")
        else:
            if self.required_permissions != tuple(sorted(set(self.required_permissions))):
                raise ValueError("Canonical requirements required")
            if self.missing_permissions != tuple(
                sorted(set(self.required_permissions) - set(self.selected_permissions))
            ):
                raise ValueError("Observed missing paths mismatch")
        return self
