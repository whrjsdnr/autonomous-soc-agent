from uuid import uuid4

import pytest

from soc_agent.approval import ApprovalRequest
from soc_agent.tools import ToolMetadata, ToolPermission, ToolRiskLevel


@pytest.fixture
def metadata() -> ToolMetadata:
    return ToolMetadata(
        name="test_tool",
        description="Fixture",
        permission=ToolPermission.SYSTEM_WRITE,
        risk_level=ToolRiskLevel.HIGH,
    )


@pytest.fixture
def pending(metadata: ToolMetadata) -> ApprovalRequest:
    return ApprovalRequest(
        incident_id=uuid4(),
        tool_name=metadata.name,
        permission=metadata.permission,
        risk_level=metadata.risk_level,
        reason="Review this proposed operation",
    )
