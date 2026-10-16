"""Real trusted model inference; injected application UTC only, no OS clock change."""

from datetime import timedelta

import pytest

import soc_agent.investigation.runtime.service as runtime_service
from soc_agent.security_ai.research.service import ResearchDemo


@pytest.mark.asyncio
async def test_actual_receipt_survives_classified_checkpoint_rollback_without_retry(
    tmp_path, monkeypatch
):
    original = runtime_service.utc_now
    created = original()
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        return created if calls == 1 else created - timedelta(seconds=0.471)

    demo = ResearchDemo(tmp_path)
    await demo.start()
    monkeypatch.setattr(runtime_service, "utc_now", clock)
    try:
        outcome = await demo.replay("quality", 0)
        record = outcome["record"]
        assert outcome["status"] == "UNKNOWN"
        assert record["receipt"]["profile"] == "quality"
        assert record["error"] == "RESEARCH_CHECKPOINT_CLOCK_ROLLBACK_NO_RETRY"
        assert record["investigation"] is None
        assert calls == 2
        again = await demo.replay("quality", 0)
        assert again["status"] == "CACHED_NO_NEW_INFERENCE"
        assert calls == 2
        snapshot = demo.snapshot()
        assert snapshot["inference_counts"] == {"quality": 1, "edge": 0}
        assert snapshot["operational_inference"] == "BLOCKED"
        assert snapshot["write_policy"] == "WRITE_DENIED"
        assert snapshot["records"] == [record]
    finally:
        await demo.stop()
