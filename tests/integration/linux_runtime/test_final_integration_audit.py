"""Fixture transport + real domain pipeline/socket; no provider or OS response calls.

Kernel-shaped journal metadata comes from existing test fixtures, not native logs.
REAL_LLM below exercises the client interface with FixtureClient, never an API.
"""

import json
import os

import pytest
from tests.integration.linux_runtime.test_invocation_recovery import FixtureClient, rows
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.linux_runtime.operator import OperatorServer, operator_request, view
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view


@pytest.mark.asyncio
@pytest.mark.parametrize("assessment_mode", ["SCRIPTED", "REAL_LLM"])
async def test_fixture_pipeline_peer_approval_simulation_and_restart(
    tmp_path, monkeypatch, assessment_mode
):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode=assessment_mode)
    client = FixtureClient(monitor.config.incident_id)
    monitor.client = client
    monitor.simulation.set_enabled(True)
    with exclusive_runtime_lock(root / "writer.lock"):
        await monitor.tick()
        await monitor.investigate_one()
        monitor.simulation.prepare_completed()
        source = read_authentication_view(monitor.pipeline)
        assert source.authentication_events_verified == 3
        assert sum(w.total for w in source.authentication_window) == 3
        assert source.inference_status == "NOT_INFERABLE"
        assert source.action_policy == "WRITE_DENIED"
        assert monitor.pipeline.queue.counts() == {"DONE": 3}
        completed = rows(monitor.store)
        assert len(completed) == 2  # Separate rule hypotheses, not six observed attempts.
        for row in completed:
            result = json.loads(row["result"])
            assert row["result_digest"] == content_digest_payload(result)
            assert result["write_disposition"] == "WRITE_DENIED"
            assert result["investigation_digest"] == content_digest_payload(result["investigation"])
            assert result["assessment_digest"] == content_digest_payload(result["assessment"])
        server = OperatorServer(monitor, (os.geteuid(),))
        await server.start()
        try:
            record = monitor.simulation.records()[0]
            identity = record.request.candidate_id
            request = {"candidate_id": identity, "expected_digest": view(record)["record_digest"]}
            assert not (await operator_request(root, "execute", **request))["ok"]
            approved = await operator_request(root, "approve", **request)
            assert approved["ok"]
            assert approved["result"]["record"]["actor_assurance"] == "OS_PEER_IDENTITY"
            assert not (await operator_request(root, "approve", **request))["ok"]
            done = await operator_request(
                root,
                "execute",
                candidate_id=identity,
                expected_digest=approved["result"]["record_digest"],
            )
            assert done["ok"] and done["result"]["status"] == "SIMULATED"
            receipt = done["result"]["record"]
            assert receipt["real_os_handler_calls"] == 0
            assert receipt["simulated_handler_calls"] == 1
            assert receipt["output"]["real_system_modified"] is False
            assert (await operator_request(root, "audit"))["ok"]
        finally:
            await server.close()
    calls = client.calls
    assert calls == (4 if assessment_mode == "REAL_LLM" else 0)
    restarted = LinuxMonitor(root, llm_client=client)
    await restarted.run(duration_seconds=0.2)
    assert rows(restarted.store) == completed
    assert client.calls == calls
    assert restarted.pipeline.queue.counts() == {"DONE": 3}
    assert read_authentication_view(restarted.pipeline) == source
    assert restarted.simulation.load(identity).model_dump(mode="json") == receipt
    assert restarted.store.verify_audit()
    with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
        await restarted.simulation.execute(identity)
    for database in (
        restarted.store.database,
        restarted.pipeline.queue.database,
        restarted.pipeline.store.database,
    ):
        with database.transaction(write=False) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
