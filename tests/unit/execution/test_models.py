from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.execution import ActionProposal


def test_defaults_and_roundtrip(action: ActionProposal) -> None:
    second = ActionProposal(
        incident_id=action.incident_id, tool_name=action.tool_name, tool_input={}
    )
    assert action.action_id.version == 4
    assert action.action_id != second.action_id
    assert action.created_at.utcoffset() == timedelta(0)
    assert ActionProposal.model_validate_json(action.model_dump_json()) == action


@pytest.mark.parametrize(
    "update",
    [
        {"tool_name": " "},
        {"extra": True},
        {"created_at": datetime(2026, 1, 1)},
        {"tool_input": []},
        {"tool_input": {"bad": object()}},
        {"tool_input": {1: "bad"}},
        {"tool_input": {"nan": float("nan")}},
        {"tool_input": {"infinity": float("inf")}},
        {"tool_input": "not json"},
    ],
)
def test_invalid_action(action: ActionProposal, update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(action.model_dump() | update)


def test_nested_input_cannot_mutate_proposal() -> None:
    raw = {"nested": {"values": ["a"]}}
    action = ActionProposal(incident_id=uuid4(), tool_name="test_tool", tool_input=raw)
    raw["nested"]["values"].append("b")
    payload = action.input_payload()
    payload["nested"]["values"].append("c")
    assert action.input_payload() == {"nested": {"values": ["a"]}}
    with pytest.raises(ValidationError):
        action.tool_input = "{}"


def test_canonical_key_order(action: ActionProposal) -> None:
    a = ActionProposal.model_validate(
        action.model_dump() | {"tool_input": {"b": 2, "a": [1, True]}}
    )
    b = ActionProposal.model_validate(
        action.model_dump() | {"tool_input": {"a": [1, True], "b": 2}}
    )
    assert a.tool_input == b.tool_input
