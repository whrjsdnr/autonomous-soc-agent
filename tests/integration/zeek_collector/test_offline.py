"""Actual official Zeek, synthetic PCAP from existing Golden Fixtures. No live input."""

import asyncio
import json
import os
from pathlib import Path

import pytest
from tests.zeek_collector_support import pcap_fixture

from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.collectors.zeek import ZeekCollector


@pytest.mark.asyncio
async def test_real_zeek_offline_golden_subset_dns_and_recovery(tmp_path):
    runner = OfflineZeek()
    try:
        runner.environment()
    except (ValueError, OSError):
        pytest.skip("OFFICIAL_ZEEK_IMAGE_NOT_INSTALLED")
    pcap = tmp_path / "golden.pcap"
    sha = pcap_fixture(pcap)
    c = ZeekCollector(tmp_path, runner=runner)
    await c.prepare(pcap=pcap, sha256=sha)
    await c.start()
    await asyncio.wait_for(c.task, 70)
    assert c.state == "STOPPED", c.last_error
    network, dns = c.network_events(), c.dns_events()
    assert len(network) == 2 and len(dns) == 1
    golden = next(e for e in network if e["source_port"] == 1000)
    assert (
        golden["duration_seconds"],
        golden["forward_packets"],
        golden["backward_packets"],
        golden["forward_ip_bytes"],
        golden["backward_ip_bytes"],
    ) == (1, 2, 1, 120, 60)
    assert (
        dns[0]["response_code"] == 0 and dns[0]["query_type"] == 1 and dns[0]["transaction_id"] == 7
    )
    assert abs(dns[0]["response_latency_seconds"] - 0.05) < 1e-6
    assert dns[0]["ttl_seconds"] == [60] and dns[0]["diagnostic"] == "MATCHED_TRANSACTION"
    assert all(e["network14_parity"] == e["dns9_parity"] == "BLOCKED" for e in network + dns)
    assert c.metrics()["inference_count"] == 0 and c.snapshot()["research"]["records"] == []
    for path in c.directory.rglob("*"):
        if path.is_file():
            assert b"Private123" not in path.read_bytes()
    assert runner.container is None and runner.process.returncode == 0
    snapshot = c.snapshot()
    audit = c.store.runtime.verify_audit()
    fresh = ZeekCollector(tmp_path)
    await fresh.recover()
    assert fresh.metrics()["network_events"] == 2 and fresh.metrics()["dns_events"] == 1
    assert fresh.rows_read == 0 and not fresh.snapshot()["collection_live"]
    if os.getenv("SOC_ZEEK_EVIDENCE"):
        Path(os.environ["SOC_ZEEK_EVIDENCE"]).write_text(
            json.dumps(
                dict(
                    scope="ACTUAL_ZEEK_9_OFFLINE_SYNTHETIC_PCAP_NOT_NATIVE",
                    pcap_sha256=sha,
                    snapshot=snapshot,
                    audit_digest=audit,
                    recovered_audit_digest=fresh.store.runtime.verify_audit(),
                    recovered_new_rows=0,
                    container_removed=runner.container is None,
                ),
                indent=2,
            )
        )
    await c.stop()
    await fresh.stop()
