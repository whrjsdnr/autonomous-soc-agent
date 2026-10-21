"""Pinned real Zeek on generated PCAPs; no sockets, live capture or model inference."""

import asyncio
import struct

import pytest
from tests.research_adapter_support import research_paths
from tests.zeek_collector_support import checksum, ip_checksum, pcap_fixture
from tests.zeek_producer_support import write_pcap

from soc_agent.security_ai.collectors.live import LiveZeekCollector


def dns_frames(path):
    pcap_fixture(path)
    body = path.read_bytes()[24:]
    rows = []
    while body:
        length = struct.unpack_from("<I", body, 8)[0]
        rows.append(body[16 : 16 + length])
        body = body[16 + length :]
    return rows[-2:]


def tcp_segment(template, *, reverse=False, seq=100, ack=0, flags=2, payload=b""):
    frame = bytearray(template[:34])
    if reverse:
        frame[26:30], frame[30:34] = frame[30:34], frame[26:30]
    sport = int.from_bytes(template[34:36], "big")
    ports = (53, sport) if reverse else (sport, 53)
    header = bytearray(struct.pack("!HHIIBBHHH", *ports, seq, ack, 80, flags, 65535, 0, 0))
    pseudo = bytes(frame[26:34]) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    header[16:18] = struct.pack("!H", checksum(pseudo + header + payload))
    frame[23] = 6
    frame[16:18] = struct.pack("!H", 20 + len(header) + len(payload))
    return ip_checksum(bytes(frame + header + payload))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario", ["tcp", "duplicate", "collision", "multiple_responses", "nxdomain", "servfail"]
)
async def test_existing_analyzer_transaction_diagnostics(tmp_path, scenario):
    query, response = dns_frames(tmp_path / "base.pcap")
    rows = [query, response]
    if scenario == "tcp":
        q, r = query[42:], response[42:]
        q, r = struct.pack("!H", len(q)) + q, struct.pack("!H", len(r)) + r
        rows = [
            tcp_segment(query),
            tcp_segment(query, reverse=True, seq=500, ack=101, flags=18),
            tcp_segment(query, seq=101, ack=501, flags=16),
            tcp_segment(query, seq=101, ack=501, flags=24, payload=q),
            tcp_segment(query, reverse=True, seq=501, ack=101 + len(q), flags=24, payload=r),
            tcp_segment(query, seq=101 + len(q), ack=501 + len(r), flags=17),
            tcp_segment(query, reverse=True, seq=501 + len(r), ack=102 + len(q), flags=17),
            tcp_segment(query, seq=102 + len(q), ack=502 + len(r), flags=16),
        ]
    elif scenario == "duplicate":
        rows = [query, query, response]
    elif scenario == "multiple_responses":
        rows = [query, response, response]
    elif scenario == "collision":
        other = bytearray(query)
        other[55] = ord("x")  # Different question, same connection/transaction ID.
        rows = [query, ip_checksum(other), response]
    else:
        other = bytearray(response[: len(query)])
        other[44:46] = struct.pack("!H", 0x8183 if scenario == "nxdomain" else 0x8182)
        other[48:50] = bytes(2)
        other[16:18] = struct.pack("!H", len(other) - 14)
        other[38:40] = struct.pack("!H", len(other) - 34)
        rows = [query, ip_checksum(other)]
    path = tmp_path / "input.pcap"
    sha = write_pcap(
        path, [(1800000000000000000 + i * 50_000_000, row) for i, row in enumerate(rows)]
    )
    c = LiveZeekCollector(tmp_path / "collector", paths=research_paths())
    try:
        await c.prepare(pcap=path, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        assert c.state == "STOPPED", c.last_error
        visibility = c.snapshot()["capture_attestation"]["dns_visibility"]
        stages = visibility["stage_counters"]
        assert stages["query_parsed"] >= 1 and stages["response_parsed"] == (
            2 if scenario == "multiple_responses" else 1
        )
        if scenario in {"collision", "duplicate", "multiple_responses"}:
            # Real Zeek can emit an unmatched summary for a duplicated pending
            # question even when another summary has a matching reply.
            if scenario == "collision":
                assert stages["transaction_ambiguous"] == 1
            assert visibility["visibility"] == "DNS_TRANSACTION_INCOMPLETE"
        else:
            assert visibility["adapter_accepted"] >= 1
            assert visibility["visibility"] == "DNS_VISIBLE"
        assert stages["question_matched"] >= 1
        if scenario == "duplicate":
            assert stages["duplicate_queries"] == 1
        if scenario == "multiple_responses":
            assert stages["multiple_responses"] == 1
        if scenario == "tcp":
            assert stages["candidate_tcp"] == len(rows)
        counters = c.stream.dns_preprocessing.snapshot()["counters"]
        if scenario == "nxdomain":
            assert counters["nxdomain_records"] == 1
        if scenario == "servfail":
            assert counters["servfail_records"] == 1
        assert c.producer.new_inferences == 0 and visibility["dns9"] == "BLOCKED"
    finally:
        await c.stop()


@pytest.mark.asyncio
async def test_privacy_dns_log_matches_stream_metadata(tmp_path):
    import json

    from soc_agent.security_ai.collectors.offline import OfflineZeek

    pcap = tmp_path / "same.pcap"
    from tests.zeek_collector_support import pcap_fixture

    sha = pcap_fixture(pcap)
    (tmp_path / "logs").mkdir(mode=0o700)
    await asyncio.to_thread(OfflineZeek().run, pcap, sha, tmp_path / "logs")
    logged = [json.loads(line) for line in (tmp_path / "logs/dns.log").read_text().splitlines()]
    c = LiveZeekCollector(tmp_path / "collector", paths=research_paths())
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        assert c.state == "STOPPED", c.last_error
        streamed = [
            json.loads(line)["data"]
            for line in (c.directory / "stream.jsonl").read_text().splitlines()
            if json.loads(line)["kind"] == "dns"
        ]
        assert len(logged) == len(streamed) == c.stream.dns_count == 1
        # UID varies per Zeek process; question text is deliberately never logged.
        keys = ("ts", "trans_id", "qtype", "rcode", "rtt", "TTLs", "TC", "proto")
        assert {k: logged[0].get(k) for k in keys} == {k: streamed[0].get(k) for k in keys}
        for key in ("orig_h", "orig_p", "resp_h", "resp_p"):
            assert logged[0]["id." + key] == streamed[0]["id"][key]
        assert "query" not in logged[0] and "query" not in streamed[0]
        assert c.store.runtime.verify_audit()
    finally:
        await c.stop()
