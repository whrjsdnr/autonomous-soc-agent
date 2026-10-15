"""Supply-model fixtures for read-only lineage, not native inference evidence."""

import json
import subprocess
from pathlib import Path

import pytest
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace
from tests.integration.external_runtime.test_runtime import host as host

from soc_agent.security_ai.external.package_status import (
    inspect_configured_packages,
    inspect_packages,
)


@pytest.mark.asyncio
async def test_revalidated_history_stays_separate_from_current_inventory(host):
    composition, store, context, *_ = host
    with store.database.transaction(write=False) as c:
        before = tuple(c.iterdump())
    status = composition.service.security_ai_status(incident_id=context.input_snapshot.incident_id)
    assert status.last_validation_check == "RECORDED"
    assert status.last_validation.context_digest == context.context_digest
    assert not status.last_validation.native_inference_this_query
    assert status.last_validation.model_bindings == tuple(
        r.binding.binding_id for r in context.results
    )
    assert all(p.demo_inference == "UNKNOWN" for p in status.packages)
    assert all(p.operational_input == "NOT_INFERABLE" for p in status.packages)
    with store.database.transaction(write=False) as c:
        assert tuple(c.iterdump()) == before


@pytest.mark.asyncio
async def test_corrupt_context_never_becomes_successful_history(host):
    composition, store, context, *_ = host
    with store.database.transaction() as c:
        c.execute("UPDATE external_contexts SET digest=?", ("0" * 64,))
    status = composition.service.security_ai_status(incident_id=context.input_snapshot.incident_id)
    assert status.last_validation_check == "BLOCKED"
    assert status.last_validation is None


@pytest.mark.parametrize("failure", ["timeout", "bad_json", "exit", "claimed_inference"])
def test_configured_interpreter_failures_do_not_fallback(monkeypatch, failure, tmp_path):
    from soc_agent.security_ai.external import package_status

    def run(command, **kwargs):
        assert command[1:3] == ["-m", "soc_agent.security_ai.external.package_status"]
        assert "SOC_LLM_API_KEY" not in kwargs["env"]
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 30)
        payload = inspect_packages().model_dump(mode="json")
        if failure == "claimed_inference":
            payload["packages"][0]["demo_inference"] = "VERIFIED"
        return subprocess.CompletedProcess(
            command,
            1 if failure == "exit" else 0,
            b"not json" if failure == "bad_json" else json.dumps(payload).encode(),
            b"fixture-secret",
        )

    monkeypatch.setenv("SOC_LLM_API_KEY", "fixture-secret")
    monkeypatch.setattr(package_status.subprocess, "run", run)
    result = inspect_configured_packages(
        artifact_root=tmp_path, interpreter=Path("/fixture/python")
    )
    assert result.environment_scope == "CONFIGURED_NATIVE_INTERPRETER"
    assert all(
        p.overall == "BLOCKED" and p.backend_dependencies == "UNKNOWN" for p in result.packages
    )
    assert "fixture-secret" not in result.model_dump_json()


def test_relative_interpreter_rejected(tmp_path):
    with pytest.raises(ValueError, match="ABSOLUTE_NATIVE_INTERPRETER_REQUIRED"):
        inspect_configured_packages(artifact_root=tmp_path, interpreter=Path("python"))
