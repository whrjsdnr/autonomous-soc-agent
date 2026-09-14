"""Record successful tool output, without interpreting investigation intent."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel
from pydantic_core import PydanticSerializationError

from soc_agent.execution import ActionProposal
from soc_agent.investigation.errors import EvidenceConversionError
from soc_agent.state import Evidence
from soc_agent.tools import ToolResult


def evidence_from_result(
    result: ToolResult[BaseModel],
    *,
    incident_id: UUID,
    expected_tool_name: str,
    observed_at: datetime,
) -> Evidence:
    """observed_at is receipt time, not an inferred source-event timestamp.

    Preserve the complete result envelope, including its registered tool name.
    No reliability, observations, hypotheses, or purpose-derived facts are invented.
    """
    if result.tool_name != expected_tool_name:
        raise EvidenceConversionError("Tool result name does not match the investigation step")
    try:
        raw_data = ActionProposal.canonical_input(result.model_dump(mode="json"))
        return Evidence(
            incident_id=incident_id,
            source=f"tool:{result.tool_name}",
            tool_name=result.tool_name,
            summary=f"{result.tool_name} investigation result",
            raw_data=raw_data,
            observed_at=observed_at,
        )
    except (ValueError, TypeError, PydanticSerializationError) as error:
        raise EvidenceConversionError("Tool result could not be serialized as evidence") from error
