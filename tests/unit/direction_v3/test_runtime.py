"""Shared capture failure blocks both domains; no privileged or model operation."""

import asyncio

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import UnknownMockAdapter, packet

from soc_agent.security_ai.operational.network_capture.direction_policy import DirectionPolicy
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "V3_OBSERVATION_BUDGET_EXCEEDED",
        "V3_ANALYSIS_BUDGET_EXCEEDED",
        "V3_ACCOUNTING_INTEGRITY_FAILED",
        "disk",
    ],
)
async def test_shared_failure_quarantine_and_recovery(tmp_path, failure):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    adapter = UnknownMockAdapter()

    async def source():
        if failure == "disk":
            owner.policy = owner.policy.model_copy(update={"disk_bytes": 1})
            yield packet(owner, 0)
        else:
            raise ValueError(failure)
            yield

    try:
        await owner.start_fixture(source(), policy=DirectionPolicy(), model_adapter=adapter)
        await asyncio.wait_for(owner.task, 5)
        snap = owner.snapshot()
        assert owner.state == "ERROR" and owner.metrics["finalization"] == "BLOCKED"
        assert owner.metrics["gap_count"] == 1 and adapter.calls == 0
        assert (
            not snap["collection_live"]
            and snap["dns"]["diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
        )
        if failure != "disk":
            assert owner.metrics["integrity_scope"] == "CAPTURE_WIDE"
        assert owner.store.runtime.verify_audit()
        assert snap["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    finally:
        await owner.stop(abort=True)
