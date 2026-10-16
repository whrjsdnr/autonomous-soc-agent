"""Wire reader + real SQLite pipeline on synthetic metadata, without helper or capture."""

import asyncio
import threading
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from tests.live_network_performance import fixture_packets, messages
from tests.live_transport_diagnostics import fixture_channel

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig


@pytest.mark.asyncio
async def test_reader_survives_sync_runtime_initialization_and_sqlite_processing(tmp_path):
    capture, sender, session = fixture_channel(tmp_path / "observer", separated=True)
    _, records = messages(session, fixture_packets(8, session.interface_id, datetime.now(UTC)))
    errors = []

    def produce():
        try:
            for record in records:
                sender.sendall(record.model_dump_json(exclude_none=True).encode())
        except OSError as e:
            errors.append(type(e).__name__)

    thread = threading.Thread(target=produce)
    thread.start()
    try:
        # Deliberately block the processor event loop beyond the sender timeout.
        # The reader must continue even before the existing Runtime is constructed.
        time.sleep(0.65)
        assert capture.terminal is not None and capture.packets.qsize() == 8
        runtime = tmp_path / "runtime"
        initialize(
            runtime, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
        )
        configure(runtime, CaptureConfig(interface="lo"))
        monitor = NetworkMonitor(
            runtime, RuntimeStore(runtime), capture=capture, generation=str(session.session_id)
        )
        capture.stop = monitor.stopped
        original = monitor.pipeline.packet

        def slow_packet(*args):
            time.sleep(0.02)
            return original(*args)

        monitor.pipeline.packet = slow_packet
        await asyncio.wait_for(monitor.run(), 5)
        assert monitor.metrics["last_error"] is None
        assert monitor.metrics["packets_collected"] == 8
        assert monitor.metrics["inference_count"] == 0
        assert monitor.pipeline.queue.counts() == {"DONE": 9}
        assert monitor.store.verify_audit()
        assert not errors and not capture.reader_thread.is_alive()
        assert capture.counter_totals == [8, 0]
    finally:
        capture.close()
        sender.close()
        thread.join(1)
    assert not thread.is_alive()
