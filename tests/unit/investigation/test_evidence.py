import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import BaseModel

from soc_agent.investigation import EvidenceConversionError
from soc_agent.investigation.evidence import evidence_from_result
from soc_agent.tools import ToolResult


class Output(BaseModel):
    values: dict[str, int]


def test_evidence_conversion_is_factual_and_deterministic() -> None:
    incident_id = uuid4()
    observed = datetime(2026, 1, 1, tzinfo=UTC)
    a = ToolResult[Output](tool_name="log_search", output=Output(values={"b": 2, "a": 1}))
    b = ToolResult[Output](tool_name="log_search", output=Output(values={"a": 1, "b": 2}))
    records = [
        evidence_from_result(
            result, incident_id=incident_id, expected_tool_name="log_search", observed_at=observed
        )
        for result in (a, b)
    ]
    assert records[0].raw_data == records[1].raw_data
    assert json.loads(records[0].raw_data) == a.model_dump(mode="json")
    assert records[0].incident_id == incident_id
    assert records[0].source == "tool:log_search"
    assert records[0].tool_name == "log_search"
    assert records[0].reliability is None
    assert records[0].observed_at == observed
    assert records[0].collected_at.tzinfo is not None


def test_wrong_tool_name_rejected() -> None:
    result = ToolResult[Output](tool_name="other", output=Output(values={}))
    with pytest.raises(EvidenceConversionError):
        evidence_from_result(
            result,
            incident_id=uuid4(),
            expected_tool_name="log_search",
            observed_at=datetime.now(UTC),
        )


def test_unserializable_output_is_conversion_failure() -> None:
    class BadOutput(BaseModel):
        value: object

    result = ToolResult[BadOutput](tool_name="test", output=BadOutput(value=object()))
    with pytest.raises(EvidenceConversionError):
        evidence_from_result(
            result, incident_id=uuid4(), expected_tool_name="test", observed_at=datetime.now(UTC)
        )
