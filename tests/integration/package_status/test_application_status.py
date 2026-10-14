"""Actual composition query and CLI; no native model/LLM execution."""

import json
import os
import subprocess
import sys

import pytest
from tests.integration.external_context_storage.test_store import bundle as bundle
from tests.integration.external_context_storage.test_store import workspace as workspace
from tests.integration.external_runtime.test_runtime import host as host


@pytest.mark.asyncio
async def test_application_status_does_not_publish_or_change_runtime(host):
    composition, store, context, registry, client, calls = host
    with store.database.transaction(write=False) as connection:
        before = tuple(connection.iterdump())
    first = composition.service.security_ai_status()
    second = composition.service.security_ai_status()
    assert first == second
    with store.database.transaction(write=False) as connection:
        assert tuple(connection.iterdump()) == before
    assert calls == {"read": 0, "write": 0}
    assert all(p.demo_inference == "UNKNOWN" for p in first.packages)
    assert first.authentication.current_runtime_validation == "NOT_QUERIED"


def test_cli_status_missing_root_sanitized(tmp_path):
    root = tmp_path / "private-model-location"
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_agent.security_ai.external.package_status",
            "--artifact-root",
            str(root),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "SOC_LLM_API_KEY": "fixture-secret-never-echo"},
    )
    assert process.returncode == 0
    value = json.loads(process.stdout)
    assert all(p["artifact"] == "BLOCKED" for p in value["packages"])
    assert str(root) not in process.stdout
    assert "fixture-secret-never-echo" not in process.stdout + process.stderr
    assert not root.exists()
