"""Independent DNS visibility and summary accounting; no live capture or query."""

from uuid import uuid4

from tests.unit.zeek_attestation.test_contract import stages
from tests.zeek_collector_support import row

from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.dns_visibility import diagnose
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.preprocessing import DNSPreprocessing


def test_visibility_gap_and_incomplete_never_promote_dns():
    good = stages(
        header_validated=2,
        analyzer_dispatch=2,
        query_parsed=1,
        response_parsed=1,
        transaction_matched=1,
        event_emitted=1,
    )
    assert diagnose(good, candidates=2, accepted=1, rejected=0)["visibility"] == "DNS_VISIBLE"
    assert (
        diagnose(good, candidates=2, accepted=1, rejected=0, capture_gap=True)["visibility"]
        == "CAPTURE_GAP"
    )
    assert (
        diagnose(
            stages(event_emitted=1, response_missing_metadata=1),
            candidates=1,
            accepted=1,
            rejected=0,
        )["visibility"]
        == "DNS_TRANSACTION_INCOMPLETE"
    )
    assert (
        diagnose(None, candidates=None, accepted=0, rejected=0)["visibility"]
        == "DNS_VISIBILITY_UNKNOWN"
    )
    assert (
        diagnose(None, candidates=None, accepted=0, rejected=0, encrypted_only=True)["visibility"]
        == "ENCRYPTED_DNS_UNOBSERVABLE"
    )


def test_duplicate_rcode_truncation_and_out_of_order_summary_accounting():
    source = Source(session_id=uuid4(), source_digest="a" * 64, origin="ZEEK_OFFLINE_PCAP")
    dns = DNSPreprocessing(source)
    first = parse_line(row("dns", rcode=3), "dns", source)
    dns.add(first)
    dns.add(first)
    second = parse_line(row("dns", uid="Other", ts=1800000000.0, rcode=2, TC=True), "dns", source)
    dns.add(second)
    value = dns.snapshot()
    assert (value["received"], value["accepted"], value["duplicate"]) == (3, 2, 1)
    assert value["counters"]["nxdomain_records"] == value["counters"]["servfail_records"] == 1
    assert value["counters"]["truncated_records"] == 1
    assert value["counters"]["out_of_order_transaction_starts"] == 1
    assert value["query_packets"] is value["response_packets"] is None
    assert value["dns9"] == "BLOCKED" and not value["fqdn_retained"]
