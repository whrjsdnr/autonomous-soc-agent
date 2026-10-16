"""Synthetic DNS wire data only. No traffic generation."""

import struct
from datetime import UTC, datetime

from soc_agent.security_ai.operational.network_capture.parsing import parse_packet
from tests.live_flow_eligibility_support import BASE_NS
from tests.streaming_network_support import packet
from tests.unit.network_capture.test_packets import dns, frame


def dns_packet(owner, t, *, response=False, tcp=False, malformed=False):
    body = bytearray(dns(b"example"))
    if response:
        body[2:4] = struct.pack("!H", 0x8180)
    ns = BASE_NS + int(t * 10**9)
    return parse_packet(
        frame(reverse=response, tcp=tcp, payload=b"x" if malformed else bytes(body)),
        interface_id=owner.session.interface_id,
        timestamp=datetime.fromtimestamp(ns // 10**9, UTC).replace(microsecond=ns % 10**9 // 1000),
        direction="OUTBOUND",
        native=False,
    )


async def total_source(owner):
    yield packet(owner, 0)
    yield packet(owner, 0.5, reverse=True, length=60, flags=16)
    yield packet(owner, 1, length=80, flags=1)
    yield dns_packet(owner, 2)
    yield dns_packet(owner, 2.25, response=True)
    yield packet(owner, 33, port=9000)
