import pytest
from pydantic import ValidationError

from soc_agent.llm import LLMRequest


def test_request_preserves_prompts_and_roundtrips() -> None:
    request = LLMRequest(system_prompt="  Instructions\n", user_prompt="Input\n")
    assert request.system_prompt == "  Instructions\n"
    assert request.user_prompt == "Input\n"
    assert LLMRequest.model_validate_json(request.model_dump_json()) == request
    with pytest.raises(ValidationError):
        request.user_prompt = "changed"


@pytest.mark.parametrize("field", ["system_prompt", "user_prompt"])
@pytest.mark.parametrize("value", ["", " \n\t", None, 123])
def test_invalid_prompts(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        LLMRequest.model_validate(
            {"system_prompt": "Instructions", "user_prompt": "Input", field: value}
        )


@pytest.mark.parametrize("field", ["system_prompt", "user_prompt"])
def test_missing_prompt(field: str) -> None:
    with pytest.raises(ValidationError):
        LLMRequest.model_validate({field: "Only one prompt"})


def test_unknown_settings_rejected() -> None:
    with pytest.raises(ValidationError):
        LLMRequest.model_validate(
            {"system_prompt": "Instructions", "user_prompt": "Input", "seed": 1}
        )
