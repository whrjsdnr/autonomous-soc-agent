"""Synthetic metadata and explicit before/after controller projection for comparison.

No socket/capture, kernel filter or suppression is installed by these helpers.
"""

from types import SimpleNamespace

from soc_agent.security_ai.research.isolated_dns import IsolatedDNS
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet

SESSION = "e1854b80-4e75-4e1c-8ce7-39a333e96d39"
OWNER = SimpleNamespace(session=SimpleNamespace(interface_id="a" * 64))


def seed_dns():
    engine = IsolatedDNS(SESSION)
    for i in range(128):
        value = dns_packet(OWNER, 0).model_copy(update={"source_port": 30000 + i})
        engine.observe(value, i + 1)
    assert engine.snapshot()["pending"] == 128
    return engine


def baseline_project(engine, value, sequence):
    projected = value.model_copy(update={"dns": None})
    events = engine.observe(value, sequence)
    snapshot = engine.snapshot()
    status = engine.snapshot()["diagnostic_status"]
    return projected, events, snapshot, status


def optimized_project(engine, value, sequence, previous):
    projected = value.model_copy(update={"dns": None}) if value.dns is not None else value
    events = engine.observe(value, sequence)
    snapshot = (
        engine.snapshot() if engine.changes_projection(value) or previous is None else previous
    )
    return projected, events, snapshot, engine.diagnostic_status


def sequence():
    return [
        packet(OWNER, 0),
        dns_packet(OWNER, 0.1),
        packet(OWNER, 99),
        dns_packet(OWNER, 0.2, response=True),
        dns_packet(OWNER, 0.3),
        dns_packet(OWNER, 0.4),
        dns_packet(OWNER, 0.5, response=True),
        dns_packet(OWNER, 0.6, malformed=True),
    ]


def pair_candidate(first, second, *, first_emission=None, second_emission=None):
    """Exact-time paired Fixture ground truth, or UNKNOWN: never authorizes suppression.

    A production kernel emission ID is absent from the approved transport. Digest
    and opposite directions alone cannot establish a physical packet identity.
    No payload/digest history is retained and no reordering window is introduced.
    """
    if first_emission is None or second_emission is None:
        return "UNKNOWN"
    same = (
        first_emission == second_emission
        and first.raw_frame_digest == second.raw_frame_digest
        and first.capture_timestamp_ns == second.capture_timestamp_ns
        and first.timestamp == second.timestamp
        and {first.direction, second.direction} == {"OUTBOUND", "INBOUND"}
        and first.interface_id == second.interface_id
    )
    return "VERIFIED_FIXTURE_PAIR" if same else "NOT_A_VERIFIED_PAIR"
