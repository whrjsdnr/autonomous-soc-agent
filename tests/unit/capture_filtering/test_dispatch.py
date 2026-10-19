"""No flow packet is suppressed, no budget moved; only redundant projection work is skipped."""

from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError
from tests.capture_filtering_support import (
    OWNER,
    SESSION,
    baseline_project,
    optimized_project,
    sequence,
)
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet

from soc_agent.security_ai.research.isolated_dns import IsolatedDNS
from soc_agent.security_ai.research.packet_accounting import packet_accounting


def test_before_after_identical_dns_and_network_provenance_every_packet():
    before, after = IsolatedDNS(SESSION), IsolatedDNS(SESSION)
    previous = None
    for i, value in enumerate(sequence(), 1):
        original = value.model_dump(mode="json")
        old = baseline_project(before, value, i)
        new = optimized_project(after, value, i, previous)
        previous = new[2]
        assert new == old
        assert value.model_dump(mode="json") == original
        if value.dns is None:
            assert new[0] is value  # Frozen object reuse, never a packet drop.
        else:
            assert new[0].dns is None and value.dns is not None
        assert after.observations == i
    assert after.snapshot() == before.snapshot()
    assert after.counts["MATCHED_RESPONSE"] == 1
    assert after.counts["AMBIGUOUS_QUERY"] == after.counts["AMBIGUOUS_RESPONSE"] == 1
    assert after.counts["PARSE_FAILURE"] == 1


def test_irrelevant_packet_does_not_expire_query_or_remove_limits():
    engine = IsolatedDNS(SESSION)
    engine.observe(dns_packet(OWNER, 0), 1)
    old = engine.snapshot()
    p = packet(OWNER, 1000)
    assert not engine.changes_projection(p)
    assert not engine.observe(p, 2)
    assert engine.snapshot() == old and engine.snapshot()["pending"] == 1
    engine.observations = 38656
    with pytest.raises(ValueError, match="TOTAL_DNS_OBSERVATION_LIMIT"):
        engine.observe(p, 3)
    with pytest.raises((ValidationError, FrozenInstanceError)):
        p.dns = None


@pytest.mark.parametrize("port", [53, 443, 853])
def test_parse_and_visibility_events_are_not_filtered(port):
    engine = IsolatedDNS(SESSION)
    p = packet(OWNER, 1).model_copy(update={"destination_port": port})
    assert engine.changes_projection(p)
    events = engine.observe(p, 1)
    assert events[0]["status"] == (
        "PARSE_FAILURE" if port == 53 else "ENCRYPTED_VISIBILITY_UNKNOWN"
    )
    assert engine.diagnostic_status == engine.snapshot()["diagnostic_status"]


def test_quarantine_blocked_privacy_and_unknown_accounting_remain_fail_closed():
    engine = IsolatedDNS(SESSION)
    engine.observe(dns_packet(OWNER, 1), 1)
    assert engine.observe(dns_packet(OWNER, 0.9), 2)[-1]["status"] == "DNS_TIMESTAMP_QUARANTINED"
    assert engine.diagnostic_status == "DEGRADED"
    engine.blocked = True
    p = packet(OWNER, 2)
    assert engine.changes_projection(p)
    engine.observe(p, 3)
    assert engine.counts["BLOCKED_PACKET_EXCLUDED"] == 1
    assert engine.diagnostic_status == "DNS_DIAGNOSTIC_BLOCKED"
    q = dns_packet(OWNER, 3)
    q = q.model_copy(update={"dns": q.dns.model_copy(update={"query_name": "private.example"})})
    with pytest.raises(ValueError, match="TOTAL_DNS_NAME_RETENTION_DENIED"):
        engine.observe(q, 4)
    account = packet_accounting({}, origin="NATIVE_AF_PACKET", session_id=SESSION)
    assert account["filtered_raw_frames"] is account["loopback_duplicate_candidates"] is None
    assert account["accepted_raw_frames"] is None and not account["rate_limit_changed"]


def test_duplicate_identity_requires_ground_truth_not_a_two_to_one_ratio():
    from tests.capture_filtering_support import pair_candidate

    first = packet(OWNER, 0)
    clone = first.model_copy(update={"direction": "INBOUND"})
    assert pair_candidate(first, clone) == "UNKNOWN"
    assert (
        pair_candidate(first, clone, first_emission=1, second_emission=1) == "VERIFIED_FIXTURE_PAIR"
    )
    assert (
        pair_candidate(first, clone, first_emission=1, second_emission=2) == "NOT_A_VERIFIED_PAIR"
    )
    later = packet(OWNER, 0.001).model_copy(update={"direction": "INBOUND"})
    assert (
        pair_candidate(first, later, first_emission=1, second_emission=1) == "NOT_A_VERIFIED_PAIR"
    )
    # Same-direction retransmissions are valid distinct inputs, never removed.
    assert (
        pair_candidate(first, first, first_emission=1, second_emission=1) == "NOT_A_VERIFIED_PAIR"
    )
