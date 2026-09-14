import pytest
from pydantic import JsonValue, ValidationError

from soc_agent.planning import LLMInvestigationPlanDraft, LLMInvestigationStepDraft


def test_valid_draft_and_schema(response: dict[str, JsonValue]) -> None:
    draft = LLMInvestigationPlanDraft.model_validate(response)
    assert draft.steps[0].tool_input == {"username": "alice"}
    schema = LLMInvestigationStepDraft.model_json_schema()
    assert set(schema["properties"]) == {"tool_name", "tool_input", "purpose"}
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "field",
    [
        "action_id",
        "step_id",
        "status",
        "approval_id",
        "risk_level",
        "permission",
        "policy_decision",
    ],
)
def test_authority_fields_rejected(response: dict[str, JsonValue], field: str) -> None:
    step = response["steps"][0] | {field: "forged"}
    with pytest.raises(ValidationError):
        LLMInvestigationStepDraft.model_validate(step)


@pytest.mark.parametrize(
    "update",
    [
        {"tool_name": " "},
        {"purpose": " "},
        {"tool_input": []},
        {"tool_input": "{}"},
        {"tool_input": {"x": object()}},
        {"tool_input": {"x": float("nan")}},
    ],
)
def test_invalid_step(response: dict[str, JsonValue], update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        LLMInvestigationStepDraft.model_validate(response["steps"][0] | update)


@pytest.mark.parametrize(
    "update", [{"goal": " "}, {"steps": []}, {"plan_id": "forged"}, {"incident_id": "forged"}]
)
def test_invalid_plan(response: dict[str, JsonValue], update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        LLMInvestigationPlanDraft.model_validate(response | update)


def test_step_limit(response: dict[str, JsonValue]) -> None:
    assert (
        len(
            LLMInvestigationPlanDraft.model_validate(
                response | {"steps": response["steps"] * 8}
            ).steps
        )
        == 8
    )
    with pytest.raises(ValidationError):
        LLMInvestigationPlanDraft.model_validate(response | {"steps": response["steps"] * 9})
