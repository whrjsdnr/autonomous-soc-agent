"""Actual RF/LR on eligible explicit FIXTURE flows; no native capture or OS response."""

import json

import pytest
from tests.live_flow_eligibility_support import manual_features, persisted_fixture

from soc_agent.security_ai.research.live_input import produce
from soc_agent.security_ai.research.live_service import LiveResearch, bound_request
from soc_agent.security_ai.research.models import SPECS, digest


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["IDLE_TIMEOUT", "ACTIVE_TIMEOUT"])
async def test_timeout_fixture_actual_two_models_advisory_and_recovery(tmp_path, kind):
    service, monitor, session, (event, flow), flows = await persisted_fixture(tmp_path, kind)
    assert len(flows) == 2 and flows[1][1].close_reason == "SHUTDOWN"
    service.directory = tmp_path
    counts = service.flow_eligibility()
    assert counts["eligible"] == counts["rejected"] == 1 and counts["pending"] == 0
    assert counts["by_close_reason"] == {kind: 1, "SHUTDOWN": 1}
    service.demo = LiveResearch(tmp_path / "demo")
    await service.demo.start()
    requests = []
    try:
        for profile in ("quality", "edge"):
            request = bound_request(monitor, session, event, flow, profile)
            assert request.origin == "FIXTURE"
            vector = produce(request)
            assert vector.values == manual_features(kind)
            assert len(vector.values) == 14
            requests.append(request)
        service.collection_done.set()
        await service._consume()
        records = service.demo.snapshot()["records"]
        assert len(records) == 2
        for record in records:
            receipt = record["receipt"]
            assert receipt["origin"] == "FIXTURE" and receipt["status"] == "RESEARCH_ONLY"
            assert receipt["producer_version"] == "1.1.0"
            assert tuple(receipt["feature_values"]) == manual_features(kind)
            assert receipt["feature_digest"] == produce(requests[0]).feature_digest
            spec = SPECS[receipt["profile"]]
            assert receipt["artifact_digest"] == spec["sha256"]
            assert receipt["model_id"] == spec["model_id"]
            assert receipt["threshold"] == spec["threshold"]
            assert receipt["operational_inference"] == "BLOCKED"
            assert record["investigation"]["status"] == "ASSESSED_READ_ONLY"
            assert record["investigation"]["checkpoint_restored"]
            assert record["investigation"]["provider_calls"] == 0
            assert not record["investigation"]["assessment"]["incident_state"]["observations"]
        assert monitor.store.verify_audit() and service.pending.empty()
        assert service.demo.adapter.process is None
        await service.demo.stop()
        restored = LiveResearch(tmp_path / "demo")
        await restored.start()
        try:
            for request in requests:
                key = digest(
                    {"session": str(session), "flow": flow.flow_id, "profile": request.profile}
                )
                assert (await restored.dispatch(request, key))[
                    "status"
                ] == "CACHED_NO_NEW_INFERENCE"
            assert restored.snapshot()["records"] == records
        finally:
            await restored.stop()
        # Keep only sanitized model/contract evidence in the private temporary test directory.
        evidence = [
            {
                k: r["receipt"][k]
                for k in (
                    "profile",
                    "origin",
                    "model_id",
                    "artifact_digest",
                    "producer_version",
                    "feature_digest",
                    "score",
                    "threshold",
                    "prediction",
                    "inference_latency_ms",
                )
            }
            for r in records
        ]
        (tmp_path / "eligibility-result.json").write_text(
            json.dumps({"kind": kind, "models": evidence})
        )
    finally:
        await service.demo.stop()
