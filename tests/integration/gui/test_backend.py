"""Existing runtime/socket/schema/runner integration; authentication inputs are fixtures."""

from pathlib import Path

import pytest
from tests.integration.restricted_response.test_executor import endpoint

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.gui.queries import investigation_rows
from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED


@pytest.mark.asyncio
async def test_all_scenarios_existing_runner_isolated(tmp_path):
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    paths = []
    for row in backend.scenario_catalog():
        result = await backend.scenario(row["id"])
        assert result["overall_status"] == "PASS"
        assert result["input_origin"] == "FIXTURE" and result["assessment_mode"] == "SCRIPTED"
        assert (
            result["real_os_handler_calls"] == 0 and result["inference_status"] == "NOT_INFERABLE"
        )
        path = Path(result["audit_path"])
        assert path.is_relative_to(backend.directory)
        assert (path.parent / "gui-result.json").is_file()
        paths.append(path)
    assert len(set(paths)) == 12


@pytest.mark.asyncio
async def test_live_socket_approval_marker_rollback_and_external_lifecycle(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, _):
        backend = Backend(GUIConfig(data_directory=tmp_path / "gui", runtime_directory=root))
        marker = root / "test-resources/marker"
        item = (await backend.operator("restricted-request", finding_id=finding))["result"]

        async def action(op, record):
            return await backend.operator(
                "restricted-" + op,
                candidate_id=record["record"]["candidate_id"],
                expected_digest=record["record_digest"],
            )

        assert not (await action("execute", item))["ok"]
        approved = (await action("approve", item))["result"]
        assert not (await action("approve", item))["ok"]
        done = await action("execute", approved)
        assert done["ok"] and marker.read_bytes() == QUARANTINED
        assert not (await action("execute", done["result"]))["ok"]
        rollback = (
            await backend.operator(
                "restricted-rollback-request",
                finding_id=finding,
                candidate_id=done["result"]["record"]["candidate_id"],
            )
        )["result"]
        accepted = (await action("approve", rollback))["result"]
        assert (await action("execute", accepted))["ok"] and marker.read_bytes() == AVAILABLE
        assert (await backend.approvals(True))[-1]["status"] == "ROLLED_BACK"
        assert investigation_rows(root)
        assert (await backend.dashboard())["ownership"] == "EXTERNAL"
        state = monitor.store.state()
        assert (await backend.close())["external_runtime_untouched"]
        assert monitor.store.state() == state
        assert monitor.store.verify_audit()
