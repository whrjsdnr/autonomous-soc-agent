"""Exact approval matching without an opaque fingerprint or tool-name lookup."""

from soc_agent.approval import ApprovalRequest
from soc_agent.execution.errors import ApprovalBindingError
from soc_agent.execution.models import ActionProposal
from soc_agent.tools import ToolMetadata


def validate_binding(
    action: ActionProposal, approval: ApprovalRequest, metadata: ToolMetadata
) -> None:
    if (
        approval.action_id != action.action_id
        or approval.incident_id != action.incident_id
        or approval.tool_name != action.tool_name
        or metadata.name != action.tool_name
        or approval.action_input_json != action.tool_input
        or approval.permission != metadata.permission
        or approval.risk_level != metadata.risk_level
    ):
        raise ApprovalBindingError("Approval does not match the exact action and tool metadata")
