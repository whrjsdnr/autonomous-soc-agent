import json
import os
from pathlib import Path
from uuid import UUID

import pytest
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.offline import OfflineZeek
from soc_agent.security_ai.collectors.packet_input import metadata, reference, verify_packets
from soc_agent.security_ai.collectors.packet_producer import aggregate


@pytest.mark.parametrize(
    "scenario,tcp,ipv6",
    [
        ("idle", True, False),
        ("idle", False, False),
        ("active", True, False),
        ("idle", True, True),
        ("idle", False, True),
    ],
)
def test_actual_zeek_packet_api_all14_golden(tmp_path, monkeypatch, scenario, tcp, ipv6):
    runner = OfflineZeek(packet_mode=True)
    try:
        runner.environment()
    except (ValueError, OSError):
        pytest.skip("OFFICIAL_ZEEK_IMAGE_NOT_INSTALLED")
    pcap = tmp_path / "input.pcap"
    sha = golden(pcap, scenario, tcp=tcp, ipv6=ipv6)
    logs = tmp_path / "logs"
    logs.mkdir()
    result = runner.run(pcap, sha, logs)
    packets = verify_packets(
        pcap, logs / "network14_packets.log", sha, result["log_sha256"]["network14_packets.log"]
    )
    assert packets == tuple(reference(pcap))
    session = str(UUID(int=1))
    proof = aggregate(packets, session)
    source = research_paths()
    monkeypatch.syspath_prepend(str((source.producer_source or source.ml) / "src"))
    from ml.verified_producers.contracts import NETWORK_NAMES
    from ml.verified_producers.network import Packet
    from ml.verified_producers.network_v1_1 import network_features

    comparisons = []
    for flow in proof["flows"]:
        # SHUTDOWN is still arithmetic-comparable, never model-eligible.
        from soc_agent.security_ai.collectors.packet_input import Packet as ZeekPacket

        window = tuple(ZeekPacket.model_validate(x) for x in flow["packets"])
        vector = network_features(
            tuple(Packet(**p) for p in metadata(window, session, sha)),
            source_origin="OFFLINE_PCAP",
            source_identity=sha,
        )
        assert (
            tuple(flow["values"]) == vector.values and tuple(flow["feature_names"]) == NETWORK_NAMES
        )
        from soc_agent.security_ai.research.models import digest

        assert (
            digest(
                dict(
                    producer_id=vector.producer_id,
                    version=vector.semantic_version,
                    configuration_digest=vector.configuration_digest,
                    source_digest=vector.source_digest,
                    feature_names=flow["feature_names"],
                    dtype="float32",
                    values=flow["values"],
                    source_origin="OFFLINE_PCAP",
                    quality="UNKNOWN",
                )
            )
            == vector.feature_digest
        )
        comparisons.append(
            dict(
                close_reason=flow["close_reason"],
                eligible=flow["eligible"],
                values=flow["values"],
                feature_digest=vector.feature_digest,
            )
        )
    assert proof["eligible"] == 1 and runner.container is None
    if os.getenv("SOC_ZEEK_PACKET_EVIDENCE"):
        out = Path(os.environ["SOC_ZEEK_PACKET_EVIDENCE"])
        out.mkdir(exist_ok=True)
        (out / f"{scenario}-{tcp}-{ipv6}.json").write_text(
            json.dumps(
                dict(
                    scope="ACTUAL_ZEEK_OFFLINE_SYNTHETIC_PCAP_NOT_NATIVE",
                    pcap_sha256=sha,
                    script_sha256=result["packet_policy_sha256"],
                    packet_count=len(packets),
                    comparisons=comparisons,
                    elapsed_seconds=result["elapsed_seconds"],
                ),
                indent=2,
            )
        )
