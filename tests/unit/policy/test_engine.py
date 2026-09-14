import pytest

from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.tools import ToolMetadata, ToolPermission, ToolRiskLevel


@pytest.mark.parametrize("permission", list(ToolPermission))
@pytest.mark.parametrize(
    "risk,read_expected,write_expected",
    [
        (ToolRiskLevel.READ_ONLY, PolicyDecision.ALLOW, PolicyDecision.DENY),
        (ToolRiskLevel.LOW, PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL),
        (ToolRiskLevel.MEDIUM, PolicyDecision.REQUIRE_APPROVAL, PolicyDecision.REQUIRE_APPROVAL),
        (ToolRiskLevel.HIGH, PolicyDecision.REQUIRE_APPROVAL, PolicyDecision.REQUIRE_APPROVAL),
        (ToolRiskLevel.DESTRUCTIVE, PolicyDecision.DENY, PolicyDecision.DENY),
    ],
)
def test_complete_default_policy(
    permission: ToolPermission,
    risk: ToolRiskLevel,
    read_expected: PolicyDecision,
    write_expected: PolicyDecision,
) -> None:
    metadata = ToolMetadata(
        name="test_tool", description="Test", permission=permission, risk_level=risk
    )
    result = PolicyEngine().evaluate(metadata)
    expected = read_expected if permission.value.endswith("_read") else write_expected
    assert result.decision is expected
    assert result.reason.strip()
    assert PolicyEngine().evaluate(metadata) == result


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {},
        "allow",
        ToolMetadata.model_construct(),
        ToolMetadata.model_construct(
            name="test_tool", description="Test", permission="unknown", risk_level="low"
        ),
        ToolMetadata.model_construct(
            name="test_tool", description="Test", permission="file_read", risk_level="unknown"
        ),
    ],
)
def test_invalid_metadata_fails_closed(metadata: object) -> None:
    assert PolicyEngine().evaluate(metadata).decision is PolicyDecision.DENY
