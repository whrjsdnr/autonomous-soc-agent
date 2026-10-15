import pytest
from tests.research_adapter_support import research_paths


@pytest.fixture(autouse=True)
def explicit_test_dependencies(monkeypatch):
    paths = research_paths()
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", lambda: paths)
