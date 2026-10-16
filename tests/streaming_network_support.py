"""Explicit synthetic packets only. No socket, OS capture, privilege or traffic."""

import asyncio
import struct
import time

from tests.live_flow_eligibility_support import BASE_NS
from tests.unit.live_network.test_parity import observation, wire


def packet(owner, t, *, reverse=False, length=40, flags=2, port=1000, tcp=True):
    body = bytearray(wire(reverse=reverse, length=length, flags=flags, tcp=tcp))
    ports = (2000, port) if reverse else (port, 2000)
    body[34:38] = struct.pack("!HH", *ports)
    value = observation(bytes(body), BASE_NS + int(t * 1e9), native=False)
    return value.model_copy(update={"interface_id": owner.session.interface_id})


async def idle_source(owner):
    for t, reverse, length, flag in (
        (0, False, 40, 2),
        (0.5, True, 60, 16),
        (1, False, 80, 1),
        (31, False, 40, 2),
    ):
        yield packet(owner, t, reverse=reverse, length=length, flags=flag)
        await asyncio.sleep(0)


class UnknownMockAdapter:
    """No model receipt or score fabricated; simulated crash returns UNKNOWN."""

    def __init__(self):
        self.calls = 0
        self.process = None
        self.authorize_live = None

    def status(self, *args):
        return {"status": "READY", "operational_inference": "BLOCKED"}

    async def infer(self, request):
        self.calls += 1
        return {"status": "UNKNOWN", "error": "MOCK_WORKER_CRASH_NO_REAL_INFERENCE"}

    async def cancel(self):
        pass


async def real_time_source(owner, seconds):
    started = time.monotonic()
    tick = 0
    while time.monotonic() - started < seconds:
        t = time.monotonic() - started
        yield packet(owner, t, port=3000, flags=16)
        cycle, phase = divmod(tick, 70)
        if phase in (0, 1, 2):
            yield packet(
                owner,
                t,
                port=10000 + cycle,
                reverse=phase == 1,
                length=40 + phase * 20,
                flags=(2, 16, 1)[phase],
            )
        tick += 1
        await asyncio.sleep(0.5)
