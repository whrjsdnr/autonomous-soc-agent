"""Different request order is not simultaneous DNS reader coalescing."""

import asyncio
import threading

import pytest
from tests.unit.continuous.test_storage_control_isolation import runtime


@pytest.mark.asyncio
async def test_data_snapshot_delayed_before_dns_read_requires_a_new_status_read(
    tmp_path, monkeypatch
):
    _, service = runtime(tmp_path)
    counts_entered, counts_release = threading.Event(), threading.Event()
    dns_entered = threading.Event()
    reads = []
    original = service.store.queue.counts

    def counts():
        counts_entered.set()
        assert counts_release.wait(3)
        return original()

    class DNSStatus:
        last_error = None

        @property
        def snapshot(self):
            reads.append(threading.get_ident())
            dns_entered.set()
            return {"state": "RUNNING", "cleanup": "NOT_STARTED"}

    monkeypatch.setattr(service.store.queue, "counts", counts)
    service.dns_source = DNSStatus()
    pending = asyncio.create_task(service.observed_snapshot())
    control = None
    try:
        assert await asyncio.to_thread(counts_entered.wait, 1)
        control = asyncio.create_task(service.control())
        assert await asyncio.to_thread(dns_entered.wait, 1)
        service.stop.set()
        await asyncio.wait_for(control, 1)
        assert len(reads) == 1
        # The data snapshot reaches DNS only after the earlier read completed.
        counts_release.set()
        await pending
        assert len(reads) == 2
        assert service.source.stop_sent.is_set()
    finally:
        counts_release.set()
        service.stop.set()
        await pending
        if control:
            await control
