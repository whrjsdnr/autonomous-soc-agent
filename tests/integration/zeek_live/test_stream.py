import asyncio
import json

import pytest
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.offline import OfflineZeek


@pytest.mark.asyncio
@pytest.mark.parametrize("tcp,ipv6", [(True, False), (False, False), (True, True), (False, True)])
async def test_actual_offline_stream_packet_dns_and_finalization(tmp_path, monkeypatch, tcp, ipv6):
    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("OFFICIAL_IMAGE_NOT_INSTALLED")

    async def no_models(self, result):
        from soc_agent.security_ai.collectors.packet_input import verify_packets

        packets = verify_packets(
            self.collector.pcap,
            self.collector.directory / "logs/network14_packets.log",
            self.collector.sha256,
            result["log_sha256"]["network14_packets.log"],
        )
        assert len(packets) == 4
        self.state = "TEST_PACKET_PARITY_ONLY"

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.producer_service.ProducerService.produce", no_models
    )
    pcap = tmp_path / "input.pcap"
    sha = golden(pcap, tcp=tcp, ipv6=ipv6)
    c = LiveZeekCollector(tmp_path)
    await c.prepare(pcap=pcap, sha256=sha)
    await c.start()
    await asyncio.wait_for(c.task, 30)
    assert c.state == "STOPPED", c.last_error
    assert c.stream.closed and c.stream.packet_count == 4
    assert c.queue_peak <= 32 and c.queue_depth == 0
    assert c.stream.finalized[0]["eligible"]
    assert c.store.counts()["network"] >= 1
    assert not c.snapshot()["collection_live"]
    assert c.process_runner.cleanup_verified
    assert json.loads((c.directory / "exit.json").read_text())["native_capture"] is False
    await c.stop()


@pytest.mark.asyncio
async def test_actual_zeek_stream_dns_query_response_privacy(tmp_path, monkeypatch):
    from tests.zeek_collector_support import pcap_fixture

    try:
        OfflineZeek().environment()
    except (OSError, ValueError):
        pytest.skip("OFFICIAL_IMAGE_NOT_INSTALLED")

    async def no_models(self, result):
        from soc_agent.security_ai.collectors.packet_input import verify_packets

        packets = verify_packets(
            self.collector.pcap,
            self.collector.directory / "logs/network14_packets.log",
            self.collector.sha256,
            result["log_sha256"]["network14_packets.log"],
        )
        assert len(packets) == 5
        self.state = "TEST_PACKET_PARITY_ONLY"

    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.producer_service.ProducerService.produce", no_models
    )
    pcap = tmp_path / "dns.pcap"
    sha = pcap_fixture(pcap)
    c = LiveZeekCollector(tmp_path)
    try:
        await c.prepare(pcap=pcap, sha256=sha)
        await c.start()
        await asyncio.wait_for(c.task, 30)
        assert c.state == "STOPPED", c.last_error
        dns = c.store.events("dns")
        assert len(dns) == 1 and dns[0]["query_type"] == 1
        assert dns[0]["response_code"] == 0 and dns[0]["ttl_seconds"] == [60.0]
        assert dns[0]["diagnostic"] == "MATCHED_TRANSACTION"
        assert dns[0]["dns9_parity"] == "BLOCKED"
        raw = (c.directory / "stream.jsonl").read_text()
        assert '"query"' not in raw and '"answers"' not in raw and '"payload"' not in raw
        assert c.stream.closed and c.stream.packet_count == 5
    finally:
        await c.stop()
