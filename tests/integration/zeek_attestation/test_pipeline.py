"""Actual offline libpcap/Zeek plus Native-protocol fixtures; no Native capture."""

import asyncio
import json

import pytest
from tests.integration.zeek_integrity.test_recovery import completed
from tests.research_adapter_support import research_paths
from tests.zeek_attestation_support import offline_counter_probe
from tests.zeek_collector_support import pcap_fixture
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.live_contract import docker_argv
from soc_agent.security_ai.collectors.offline import OfflineZeek


@pytest.mark.asyncio
async def test_actual_offline_libpcap_unsupported_is_not_zero(tmp_path):
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("PINNED_IMAGE_NOT_AVAILABLE")
    path = tmp_path / "input.pcap"
    golden(path)
    value = offline_counter_probe(path)
    assert value["return_code"] < 0 and value["retrieval"] == "UNSUPPORTED"
    assert value["received"] is value["dropped"] is None
    assert value["native_attestation"] == "BLOCKED" and "1.10.5" in value["version"]
    import os
    from pathlib import Path

    if os.getenv("SOC_LIBPCAP_OFFLINE_EVIDENCE"):
        Path(os.environ["SOC_LIBPCAP_OFFLINE_EVIDENCE"]).write_text(json.dumps(value, indent=2))


@pytest.mark.asyncio
async def test_actual_zeek_dns_stage_callbacks_query_reply_and_native_gate(tmp_path):
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("PINNED_IMAGE_NOT_AVAILABLE")
    pcap = tmp_path / "input.pcap"
    sha = pcap_fixture(pcap)
    c = LiveZeekCollector(tmp_path, paths=research_paths())
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        assert c.state == "STOPPED", c.last_error
        value = c.snapshot()["capture_attestation"]
        stages = value["dns_visibility"]["stage_counters"]
        assert stages["candidate_udp"] == 2
        assert stages["header_validated"] == stages["analyzer_dispatch"] == 2
        assert stages["query_parsed"] == stages["response_parsed"] == 1
        assert stages["transaction_matched"] == stages["event_emitted"] == 1
        assert value["dns_visibility"]["adapter_accepted"] == 1
        assert value["dns_visibility"]["classification"] == "DNS_METADATA_OBSERVED"
        assert value["attestation"]["retrieval"] == "UNKNOWN"
        assert value["attestation"]["drop_count"] is None
        assert value["attestation"]["verdict"] == "UNVERIFIED" and value["native_ai"] == "BLOCKED"
        assert c.producer.new_inferences == 0  # No timeout-eligible flow in this DNS fixture.
        import os
        from pathlib import Path

        if os.getenv("SOC_DNS_STAGE_EVIDENCE"):
            Path(os.environ["SOC_DNS_STAGE_EVIDENCE"]).write_text(json.dumps(value, indent=2))
    finally:
        await c.stop()


@pytest.mark.asyncio
async def test_native_evidence_recovery_tamper_and_mount_contract(tmp_path, monkeypatch):
    c = await completed(tmp_path, monkeypatch)
    value = c.snapshot()["capture_attestation"]
    assert value["attestation"]["same_handle_proof"].startswith("BLOCKED")
    assert value["attestation"]["retrieval"] == "UNKNOWN"
    assert value["dns_visibility"]["stage_counters"] is None
    assert value["dns_visibility"]["classification"] == "DNS_VISIBILITY_UNKNOWN"
    argv = docker_argv(c.plan, c.directory)
    assert any("target=/policy/visibility.zeek,readonly" in a for a in argv)
    audit = c.store.runtime.verify_audit()
    await c.stop()
    restored = LiveZeekCollector(tmp_path)
    result = await restored.recover()
    assert result["capture_attestation"] == value
    assert restored.store.runtime.verify_audit() == audit and restored.task is None
    await restored.stop()
    p = c.directory / "capture-attestation.json"
    body = json.loads(p.read_text())
    body["attestation"]["verdict"] = "VERIFIED"
    p.write_text(json.dumps(body))
    blocked = LiveZeekCollector(tmp_path)
    result = await blocked.recover()
    assert (
        result["state"] == "ERROR" and result["last_error"] == "ZEEK_ATTESTATION_BINDING_MISMATCH"
    )
    assert blocked.task is None and blocked.producer is None
    await blocked.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("short_header", "DNS_HEADER_INVALID"),
        ("query_only", "DNS_RESPONSE_MISSING"),
        ("bad_opcode", "DNS_PARSE_FAILED"),
    ],
)
async def test_actual_zeek_dns_negative_paths(tmp_path, scenario, expected):
    import struct

    from tests.zeek_collector_support import ip_checksum
    from tests.zeek_producer_support import write_pcap

    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("PINNED_IMAGE_NOT_AVAILABLE")
    path = tmp_path / "source.pcap"
    pcap_fixture(path)
    frames = []
    with path.open("rb") as f:
        f.read(24)
        while row := f.read(16):
            _, _, n, _ = struct.unpack("<IIII", row)
            frames.append(f.read(n))
    query = bytearray(frames[-2])
    if scenario == "short_header":
        query = query[:47]
        query[16:18] = struct.pack("!H", len(query) - 14)
        query[38:40] = struct.pack("!H", len(query) - 34)
    elif scenario == "bad_opcode":
        query[44:46] = struct.pack("!H", 0x7800)
    pcap = tmp_path / "input.pcap"
    sha = write_pcap(pcap, [(1800000000000000000, ip_checksum(query))])
    c = LiveZeekCollector(tmp_path, paths=research_paths())
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 40)
        assert c.state == "STOPPED", c.last_error
        v = c.snapshot()["capture_attestation"]
        assert v["dns_visibility"]["candidate_packets"] == 1
        assert v["dns_visibility"]["classification"] == expected
        assert v["native_ai"] == v["dns9"] == "BLOCKED"
        assert v["attestation"]["drop_count"] is None and c.producer.new_inferences == 0
    finally:
        await c.stop()
