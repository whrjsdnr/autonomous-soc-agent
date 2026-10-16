"""Synthetic packet/time fixtures; no sockets, privilege, traffic or native capture."""

import math
import struct
import threading
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.capture import interface_identity
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.research.live_input import lifecycle_eligible
from soc_agent.security_ai.research.live_service import LiveMonitoring
from tests.unit.live_network.test_parity import observation, wire

BASE_NS = 1767225600 * 10**9  # Fixed epoch, not an execution timestamp.


def packet_specs(kind):
    if kind == "IDLE_TIMEOUT":
        return [(0, False, 40, 2), (0.5, True, 60, 16), (1, False, 80, 1), (31, False, 40, 2)]
    if kind == "ACTIVE_TIMEOUT":
        return [
            (i * 20, bool(i % 2), 40 + (i % 3) * 20, 2 if i == 0 else 1 if i == 5 else 16)
            for i in range(7)
        ]
    raise ValueError("UNKNOWN_FIXTURE_KIND")


def fixture_observations(kind, *, native=False):
    return tuple(
        observation(
            wire(reverse=reverse, length=length, flags=flags), BASE_NS + int(t * 1e9), native
        )
        for t, reverse, length, flags in packet_specs(kind)
    )


def manual_features(kind):
    # Separate hand arithmetic, not a second invocation of the production Producer.
    values = (
        (1, 2, 1, 120, 60, 40, 80, 60, math.sqrt(800 / 3), 1, 1, 0, 0.5, 0.5)
        if kind == "IDLE_TIMEOUT"
        else (100, 3, 3, 180, 180, 40, 80, 60, math.sqrt(800 / 3), 1, 1, 0, 20, 20)
    )
    return tuple(struct.unpack("!f", struct.pack("!f", n))[0] for n in values)


class CompletedPacketFixture:
    """Complete synthetic feed; does not attest real AF_PACKET/counter readiness."""

    def __init__(self, identity, kind):
        self.identity, self.kind = identity, kind
        self.closed = threading.Event()
        self.delivered = 0
        self.last = None
        self.sampled = False
        self.specs = packet_specs(kind)

    def open(self):
        pass

    def receive(self):
        if self.delivered == len(self.specs):
            self.stop.set()
            return None
        t, reverse, length, flags = self.specs[self.delivered]
        ns = BASE_NS + int(t * 1e9)
        self.last = datetime.fromtimestamp(ns // 10**9, UTC).replace(microsecond=ns % 10**9 // 1000)
        self.delivered += 1
        return wire(reverse=reverse, length=length, flags=flags), self.last, "OUTBOUND"

    def flow_watermark(self, now):
        return self.last or now

    def statistics(self):
        value = (0 if self.sampled else len(self.specs), 0)
        self.sampled = True
        return value

    def completion_verified(self):
        return self.delivered == len(self.specs)

    def close(self, **kwargs):
        self.closed.set()


async def persisted_fixture(root, kind):
    identity, session = interface_identity("lo"), uuid4()
    service = LiveMonitoring(root / "owner")
    capture = CompletedPacketFixture(identity, kind)
    directory = root / "runtime"
    initialize(
        directory, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
    )
    configure(directory, CaptureConfig(interface="lo", origin="EXPLICIT_PACKET_FIXTURE"))
    monitor = NetworkMonitor(
        directory,
        RuntimeStore(directory),
        capture=capture,
        generation=str(session),
        flow_handler=service.on_flow,
    )
    capture.stop = monitor.stopped
    service.monitor, service.capture = monitor, capture
    service.session = SimpleNamespace(session_id=session, interface_id=identity)
    await monitor.run()
    assert monitor.metrics["finalization"] == "VERIFIED", monitor.metrics
    with monitor.pipeline.queue.database.transaction(write=False) as c:
        rows = c.execute(
            "SELECT * FROM realtime_events WHERE json_extract(payload,'$.metadata.code')='flow'"
        ).fetchall()
    flows = []
    for row in rows:
        event = monitor.pipeline.queue._decode(row)
        flow = monitor.pipeline.decode(event)
        flows.append((event, flow))
    eligible = [(event, flow) for event, flow in flows if lifecycle_eligible(flow.close_reason)]
    assert len(eligible) == 1 and eligible[0][1].close_reason == kind
    return service, monitor, session, eligible[0], flows
