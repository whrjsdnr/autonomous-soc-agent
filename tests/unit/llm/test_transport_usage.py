"""Usage absent or malformed is UNKNOWN, never fabricated as zero."""

import json

import pytest
from pydantic import BaseModel

from soc_agent.llm.models import LLMRequest
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings


class Output(BaseModel):
    value: int


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        (None, None),
        ({"prompt_tokens": True, "completion_tokens": 3}, None),
        ({"prompt_tokens": -1, "completion_tokens": 2}, None),
        (
            {"prompt_tokens": 11, "completion_tokens": 7},
            {"prompt_tokens": 11, "completion_tokens": 7},
        ),
    ],
)
@pytest.mark.asyncio
async def test_usage_is_validated_and_missing_stays_unknown(monkeypatch, usage, expected):
    client = OpenAICompatibleClient(
        OpenAICompatibleSettings(
            base_url="https://fixture.invalid/v1", model="fixture", api_key="fixture-only-key"
        )
    )
    payload = {"choices": [{"finish_reason": "stop", "message": {"content": '{"value":1}'}}]}
    if usage is not None:
        payload["usage"] = usage
    monkeypatch.setattr(client, "_post", lambda body: json.dumps(payload).encode())
    output = await client.generate_structured(
        request=LLMRequest(system_prompt="fixture", user_prompt="fixture"), response_model=Output
    )
    assert output.value == 1
    assert client.last_usage == expected
