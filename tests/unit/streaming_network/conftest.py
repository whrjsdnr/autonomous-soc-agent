import pytest
from tests.research_adapter_support import research_paths


@pytest.fixture(autouse=True)
def dependencies(monkeypatch):
    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    monkeypatch.setattr("soc_agent.security_ai.research.adapter.defaults", lambda: paths)
