"""Preserve a published TCX failure while later DNS and cleanup errors drain."""

from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_runtime import make

from soc_agent.continuous.service import ContinuousRuntime

CODE = "CONTINUOUS_PRODUCER_RECEIVE_TIMEOUT"


@pytest.mark.asyncio
async def test_published_source_failure_survives_later_dns_error(tmp_path):
    directory, _ = make(tmp_path)
    source = SimpleNamespace(failure={"code": CODE})
    runtime = ContinuousRuntime(directory, source=source)
    assert runtime.snapshot()["last_error"] == CODE

    class DNS:
        async def events(self):
            raise RuntimeError("HELPER_HEARTBEAT_OR_PROCESS_STALE")
            yield  # pragma: no cover

    runtime.dns_source = DNS()
    with pytest.raises(RuntimeError, match="HELPER_HEARTBEAT"):
        await runtime.collect_dns()
    assert runtime.last_error == CODE
    runtime.dns_source = None
    assert runtime.snapshot()["last_error"] == CODE


def test_existing_primary_error_is_not_replaced_by_source_failure(tmp_path):
    directory, _ = make(tmp_path)
    runtime = ContinuousRuntime(directory, source=SimpleNamespace(failure={"code": CODE}))
    runtime.last_error = "EARLIER_STORAGE_FAILURE"
    assert runtime.snapshot()["last_error"] == "EARLIER_STORAGE_FAILURE"


@pytest.mark.asyncio
async def test_collector_trace_retained_when_primary_was_already_published(tmp_path):
    directory, store = make(tmp_path)

    class Source:
        failure = {"code": CODE}

        async def events(self):
            raise ValueError(CODE)
            yield  # pragma: no cover

        async def close(self):
            pass

    runtime = ContinuousRuntime(directory, source=Source())
    assert runtime.snapshot()["last_error"] == CODE
    await runtime.collect()
    assert runtime.last_error == CODE
    assert runtime.collector_failure["code"] == CODE
    assert runtime.collector_failure["origin"][-1]["function"] == "events"
    assert runtime.done.is_set()
    assert store.queue.counts() == {}
