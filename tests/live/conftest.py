"""Opt-in before any configuration resolution or live client construction."""

import os

import pytest
from pydantic import ValidationError

from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings


def require_live_llm() -> OpenAICompatibleClient:
    if os.environ.get("RUN_LIVE_LLM_TESTS") != "1":
        pytest.skip("Live LLM tests require explicit RUN_LIVE_LLM_TESTS=1")
    try:
        settings = OpenAICompatibleSettings()
    except ValidationError:
        pytest.skip("CONFIGURATION: required live LLM configuration unavailable or invalid")
    return OpenAICompatibleClient(settings)


@pytest.fixture
def live_client() -> OpenAICompatibleClient:
    return require_live_llm()
