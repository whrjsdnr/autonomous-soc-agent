import importlib.util
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError

from soc_agent.llm import LLMRequest, LLMResponseValidationError, LLMTimeoutError
from soc_agent.llm.openai_compatible import (
    LLMNetworkError,
    LLMProviderError,
    OpenAICompatibleClient,
    OpenAICompatibleSettings,
    _NoRedirect,
)

TOKEN = "super-secret-test-token"


class Output(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: int


@pytest.fixture
def settings():
    return OpenAICompatibleSettings(
        base_url="https://provider.invalid/v1", model="test-model", api_key=SecretStr(TOKEN)
    )


@pytest.mark.parametrize("flag", [None, "0", "false", "true"])
def test_gate_before_configuration_and_client(monkeypatch, flag):
    spec = importlib.util.spec_from_file_location(
        "live_gate", Path(__file__).parents[2] / "live" / "conftest.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if flag is None:
        monkeypatch.delenv("RUN_LIVE_LLM_TESTS", raising=False)
    else:
        monkeypatch.setenv("RUN_LIVE_LLM_TESTS", flag)

    def forbidden():
        raise AssertionError("Default tests must not resolve live settings")

    monkeypatch.setattr(module, "OpenAICompatibleSettings", forbidden)
    with pytest.raises(pytest.skip.Exception, match="explicit"):
        module.require_live_llm()


def test_opt_in_missing_configuration_skips(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "live_gate", Path(__file__).parents[2] / "live" / "conftest.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("RUN_LIVE_LLM_TESTS", "1")
    for name in ("SOC_LLM_BASE_URL", "SOC_LLM_MODEL", "SOC_LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(pytest.skip.Exception, match="CONFIGURATION"):
        module.require_live_llm()


def test_secret_repr_and_configuration_validation(settings):
    assert TOKEN not in repr(settings)
    assert TOKEN not in settings.model_dump_json()
    with pytest.raises(ValidationError) as error:
        OpenAICompatibleSettings(base_url=TOKEN, model="test", api_key=TOKEN)
    assert TOKEN not in str(error.value)
    assert _NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid") is None


@pytest.mark.asyncio
async def test_structured_request_and_local_validation(settings, monkeypatch):
    monkeypatch.setenv("SOC_LLM_MAX_COMPLETION_TOKENS", "3072")
    settings = OpenAICompatibleSettings(
        base_url=settings.base_url, model=settings.model, api_key=settings.api_key
    )
    client = OpenAICompatibleClient(settings)
    calls = []

    def post(body):
        calls.append(json.loads(body))
        return json.dumps(
            {"choices": [{"finish_reason": "stop", "message": {"content": '{"value": 4}'}}]}
        ).encode()

    monkeypatch.setattr(client, "_post", post)
    result = await client.generate_structured(
        request=LLMRequest(system_prompt="Return JSON", user_prompt="test"), response_model=Output
    )
    assert result.value == 4
    assert len(calls) == 1
    assert calls[0]["response_format"]["type"] == "json_schema"
    assert calls[0]["max_completion_tokens"] == 3072
    assert TOKEN not in json.dumps(calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("content", ['{"value": "wrong"}', '{"value": 1, "extra": true}', "bad"])
async def test_invalid_provider_output_not_retried(settings, monkeypatch, content):
    client = OpenAICompatibleClient(settings)
    calls = []

    def post(body):
        calls.append(body)
        return json.dumps(
            {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
        ).encode()

    monkeypatch.setattr(client, "_post", post)
    with pytest.raises(LLMResponseValidationError):
        await client.generate_structured(
            request=LLMRequest(system_prompt="JSON", user_prompt="test"), response_model=Output
        )
    assert len(calls) == 1


@pytest.mark.parametrize("kind", ["provider", "network", "timeout"])
def test_transport_errors_sanitized(settings, monkeypatch, kind):
    errors = {
        "provider": HTTPError("https://provider.invalid", 401, TOKEN, {}, None),
        "network": URLError(TOKEN),
        "timeout": TimeoutError(TOKEN),
    }

    class Opener:
        def open(self, request, timeout):
            assert request.get_header("Authorization") == "Bearer " + TOKEN
            assert timeout == 60
            raise errors[kind]

    monkeypatch.setattr("soc_agent.llm.openai_compatible.build_opener", lambda *args: Opener())
    with pytest.raises((LLMProviderError, LLMNetworkError, LLMTimeoutError)) as error:
        OpenAICompatibleClient(settings)._post(b"{}")
    assert TOKEN not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("envelope", "diagnostic"),
    [
        (b"not-json", "invalid response envelope JSON"),
        (b"{}", "invalid response envelope"),
        (
            b'{"choices":[{"finish_reason":"length","message":{"content":""}}]}',
            "token limit reached",
        ),
        (
            b'{"choices":[{"finish_reason":"stop","message":{"content":"not-json"}}]}',
            "content is not JSON",
        ),
    ],
)
async def test_failure_stage_diagnostic(settings, monkeypatch, envelope, diagnostic):
    client = OpenAICompatibleClient(settings)
    monkeypatch.setattr(client, "_post", lambda body: envelope)
    with pytest.raises(LLMResponseValidationError, match=diagnostic):
        await client.generate_structured(
            request=LLMRequest(system_prompt="JSON", user_prompt="test"), response_model=Output
        )


@pytest.mark.asyncio
async def test_schema_diagnostic_does_not_disclose_values_or_extra_field_names(
    settings, monkeypatch
):
    client = OpenAICompatibleClient(settings)
    content = json.dumps({"value": TOKEN, TOKEN: TOKEN})
    envelope = json.dumps(
        {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
    ).encode()
    monkeypatch.setattr(client, "_post", lambda body: envelope)
    with pytest.raises(LLMResponseValidationError) as error:
        await client.generate_structured(
            request=LLMRequest(system_prompt="JSON", user_prompt="test"), response_model=Output
        )
    message = str(error.value)
    assert "value: int_parsing" in message
    assert "[unknown-field]: extra_forbidden" in message
    assert TOKEN not in message
    assert error.value.__suppress_context__


def test_default_output_budget(settings, monkeypatch):
    monkeypatch.delenv("SOC_LLM_MAX_COMPLETION_TOKENS", raising=False)
    configured = OpenAICompatibleSettings(
        base_url=settings.base_url, model=settings.model, api_key=settings.api_key
    )
    assert configured.max_completion_tokens == 4096
    assert OpenAICompatibleSettings.model_fields["max_completion_tokens"].default == 4096
