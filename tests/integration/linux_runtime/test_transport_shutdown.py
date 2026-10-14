"""Blocked transport is a fixture; timeout must not join the default executor."""

import asyncio
import threading

import pytest

from soc_agent.llm.errors import LLMTimeoutError
from soc_agent.llm.models import LLMRequest
from soc_agent.llm.openai_compatible import (
    LLMNetworkError,
    OpenAICompatibleClient,
    OpenAICompatibleSettings,
)
from soc_agent.planning.models import LLMInvestigationPlanDraft


@pytest.mark.asyncio
async def test_timeout_has_no_default_executor_and_rejects_second_transport(monkeypatch):
    settings = OpenAICompatibleSettings(
        base_url="https://fixture.invalid/v1",
        model="fixture",
        api_key="fixture-secret",
        timeout_seconds=0.02,
    )
    client = OpenAICompatibleClient(settings)
    release = threading.Event()

    def blocked(body):
        release.wait(2)
        return b"{}"

    monkeypatch.setattr(client, "_post", blocked)
    request = LLMRequest(system_prompt="fixture", user_prompt="fixture")
    try:
        with pytest.raises(LLMTimeoutError):
            await client.generate_structured(
                request=request, response_model=LLMInvestigationPlanDraft
            )
        assert asyncio.get_running_loop()._default_executor is None
        with pytest.raises(LLMNetworkError, match="still active"):
            await client.generate_structured(
                request=request, response_model=LLMInvestigationPlanDraft
            )
    finally:
        release.set()
        await asyncio.sleep(0.02)
