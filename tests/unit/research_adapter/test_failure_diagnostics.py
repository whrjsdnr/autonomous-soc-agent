"""Pre-inference failure diagnostics cannot disclose exception text or start workers."""

import json
from uuid import uuid4

import pytest
from tests.research_adapter_support import research_paths

from soc_agent.security_ai.research import adapter
from soc_agent.security_ai.research.models import Request


@pytest.mark.asyncio
async def test_dependency_runtime_failure_records_stage_without_secret(tmp_path, monkeypatch):
    secret = "PRIVATE_EXCEPTION_CONTENT_NOT_FOR_LOGS"

    def failed(*args, **kwargs):
        raise RuntimeError(secret)

    async def no_process(*args, **kwargs):
        pytest.fail("Dependency failure must stop before worker spawn")

    monkeypatch.setattr(adapter, "verify", failed)
    monkeypatch.setattr(adapter.asyncio, "create_subprocess_exec", no_process)
    service = adapter.ResearchAdapter(tmp_path / "work", paths=research_paths())
    result = await service.infer(
        Request(research_mode=True, profile="quality", flow_index=0, invocation_id=uuid4())
    )
    assert result["status"] == "UNKNOWN"
    assert service.last_failure["stage"] == "DEPENDENCY_INTEGRITY"
    assert service.last_failure["error_type"] == "RuntimeError"
    assert secret not in json.dumps(service.last_failure)
    assert not (tmp_path / "work").exists()
