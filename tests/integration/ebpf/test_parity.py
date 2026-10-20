"""Same shared C parser + independent PCAP/ML v1.1.0; never EBPF Native parity."""

import json
import os
from pathlib import Path

import pytest
from tests.ebpf_support import parser, plan
from tests.research_adapter_support import research_paths
from tests.zeek_producer_support import golden

from soc_agent.security_ai.collectors.packet_input import Packet, metadata, reference
from soc_agent.security_ai.collectors.packet_producer import aggregate
from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.research.models import digest


def frames(path):
    import struct

    with path.open("rb") as f:
        f.read(24)
        while row := f.read(16):
            sec, usec, size, _ = struct.unpack("<IIII", row)
            yield sec * 10**9 + usec * 1000, f.read(size)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario,tcp,ipv6",
    [
        ("idle", True, False),
        ("active", True, False),
        ("idle", False, False),
        ("idle", True, True),
        ("idle", False, True),
    ],
)
async def test_actual_shared_c_parser_all14_ml_parity(tmp_path, monkeypatch, scenario, tcp, ipv6):
    source = tmp_path / "source.pcap"
    sha = golden(source, scenario, tcp=tcp, ipv6=ipv6)
    p = plan()
    c = EBPFCollector(tmp_path / "session", p)
    await c.prepare()
    c.begin_fixture(0)
    execute = parser(tmp_path)
    for i, (ns, body) in enumerate(frames(source), 1):
        status, raw = execute(body, ns, i)
        assert status == 0
        c.ingest(raw, monotonic=i)
        c.drain()
    await c.stop()
    expected = aggregate(tuple(reference(source)), str(p.session_id))
    assert [f["values"] for f in c.flow.finalized] == [f["values"] for f in expected["flows"]]
    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    from ml.verified_producers.contracts import NETWORK_NAMES
    from ml.verified_producers.network import Packet as MLPacket
    from ml.verified_producers.network_v1_1 import network_features

    rows = []
    for actual, expected_flow in zip(c.flow.finalized, expected["flows"], strict=True):
        window = tuple(Packet.model_validate(x) for x in expected_flow["packets"])
        vector = network_features(
            tuple(MLPacket(**v) for v in metadata(window, str(p.session_id), sha)),
            source_origin="OFFLINE_PCAP",
            source_identity=sha,
        )
        assert tuple(actual["values"]) == vector.values
        assert tuple(actual["feature_names"]) == NETWORK_NAMES
        assert actual["values_digest"] == digest(vector.values)
        assert actual["close_reason"] == expected_flow["close_reason"]
        rows.append(
            dict(
                close_reason=actual["close_reason"],
                values=actual["values"],
                numeric_digest=actual["values_digest"],
                independent_ml_fixture_digest=vector.feature_digest,
            )
        )
    assert c.network_events() == [] and c.snapshot()["ebpf"]["native_ai"] == "BLOCKED"
    with c.store.database.transaction(write=False) as db:
        text = db.execute("SELECT value FROM ebpf_checkpoint").fetchone()[0]
        assert "192.0.2." not in text and '"packets"' not in text
    if os.getenv("SOC_EBPF_PARITY_EVIDENCE"):
        out = Path(os.environ["SOC_EBPF_PARITY_EVIDENCE"])
        out.mkdir(exist_ok=True)
        (out / f"{scenario}-{tcp}-{ipv6}.json").write_text(
            json.dumps(
                dict(
                    scope="HOST_C_PARSER_AND_OFFLINE_ML_FIXTURE_NOT_KERNEL_VERIFIER_OR_NATIVE_PARITY",
                    packet_count=c.accepted,
                    comparisons=rows,
                    queue_peak=c.queue_peak,
                    audit_digest=c.store.verify_audit(),
                    native_ai="BLOCKED",
                ),
                indent=2,
            )
        )
