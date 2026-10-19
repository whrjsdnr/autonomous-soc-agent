import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.dns_parity import report
from soc_agent.security_ai.collectors.packet_input import reference
from soc_agent.security_ai.collectors.packet_producer import aggregate
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.zeek_input import ZeekRequest


def test_dns9_actual_order_units_scaler_and_blocked_projection():
    r = report()
    assert r["status"] == "BLOCKED" and r["feature_values"] is None and not r["raw_names_retained"]
    assert len(r["feature_mapping"]) == 9 and all(
        f["classification"] == "MISSING" for f in r["feature_mapping"]
    )
    assert all(f["query_api_candidate"] == "SEMANTIC_MISMATCH" for f in r["feature_mapping"])
    source = Path(__file__).resolve().parents[4] / "ML"
    contract = json.loads(
        (source / "packages/dns-security-ai/src/dns_security_ai/feature_contract.json").read_text()
    )
    assert [f["name"] for f in r["feature_mapping"]] == [
        f["name"] for f in contract["ordered_features"]
    ]
    assert all("UNVERIFIED" in f["unit"] for f in contract["ordered_features"])
    assert "scaler" in contract["preprocessing"].lower()


def request(tmp_path):
    p = tmp_path / "input.pcap"
    sha = golden(p)
    flow = aggregate(tuple(reference(p)), str(UUID(int=1)))["flows"][0]
    return ZeekRequest(
        research_mode=True,
        profile="quality",
        invocation_id=uuid4(),
        capture_session=UUID(int=1),
        flow_id=flow["flow_id"],
        provenance_digest="a" * 64,
        pcap_sha256=sha,
        packet_log_sha256="b" * 64,
        script_sha256="c" * 64,
        close_reason=flow["close_reason"],
        packets=flow["packets"],
        feature_values=flow["values"],
    )


@pytest.mark.asyncio
async def test_arbitrary_zeek_metadata_never_authorizes_model_invocation(tmp_path):
    r = request(tmp_path)
    adapter = ResearchAdapter(tmp_path, live_metadata=True)
    assert await adapter.infer(r) == {"status": "UNKNOWN", "error": "ZEEK_SOURCE_NOT_VERIFIED"}
    assert adapter.process is None
    with pytest.raises(ValueError):
        ZeekRequest.model_validate({**r.model_dump(), "feature_values": [0] * 14})
    with pytest.raises(ValueError):
        ZeekRequest.model_validate({**r.model_dump(), "close_reason": "SHUTDOWN"})
