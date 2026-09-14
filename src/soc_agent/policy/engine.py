"""Fixed default policy, evaluated without I/O or model inference."""

from pydantic import ValidationError

from soc_agent.policy.models import PolicyDecision, PolicyResult
from soc_agent.tools.enums import ToolPermission, ToolRiskLevel
from soc_agent.tools.models import ToolMetadata


class PolicyEngine:
    """Evaluate trusted declarations, not the actual behavior of an implementation.

    Invalid inputs fail closed with DENY. Even model instances are revalidated.
    This decision is not an execution token; future callers must enforce it.
    """

    def evaluate(self, metadata: ToolMetadata) -> PolicyResult:
        if not isinstance(metadata, ToolMetadata):
            return PolicyResult(decision=PolicyDecision.DENY, reason="Invalid tool metadata")
        try:
            validated = ToolMetadata.model_validate(metadata.model_dump(warnings=False))
        except ValidationError:
            return PolicyResult(decision=PolicyDecision.DENY, reason="Invalid tool metadata")
        read_permissions = (
            ToolPermission.SYSTEM_READ,
            ToolPermission.NETWORK_READ,
            ToolPermission.FILE_READ,
        )
        write_permissions = (
            ToolPermission.SYSTEM_WRITE,
            ToolPermission.NETWORK_WRITE,
            ToolPermission.FILE_WRITE,
        )
        permission, risk = validated.permission, validated.risk_level
        if permission not in (*read_permissions, *write_permissions):
            return PolicyResult(decision=PolicyDecision.DENY, reason="Unsupported permission")
        if risk == ToolRiskLevel.DESTRUCTIVE:
            return PolicyResult(
                decision=PolicyDecision.DENY, reason="Destructive actions are denied"
            )
        if permission in write_permissions and risk == ToolRiskLevel.READ_ONLY:
            return PolicyResult(
                decision=PolicyDecision.DENY, reason="Write access contradicts read-only risk"
            )
        if risk in (ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH):
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="Medium/high risk requires human approval",
            )
        if permission in write_permissions and risk == ToolRiskLevel.LOW:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="Write access requires human approval",
            )
        if permission in read_permissions and risk in (ToolRiskLevel.READ_ONLY, ToolRiskLevel.LOW):
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reason="Read access with read-only/low risk is allowed",
            )
        return PolicyResult(decision=PolicyDecision.DENY, reason="Unsupported risk level")
