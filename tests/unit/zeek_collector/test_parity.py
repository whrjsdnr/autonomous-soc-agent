"""Two different valid packet traces have the same conn.log aggregate fields."""

from dataclasses import replace

from tests.research_adapter_support import research_paths
from tests.unit.live_network.test_parity import request

from soc_agent.security_ai.collectors.parity import NETWORK14, report, require_inference
from soc_agent.security_ai.research.live_input import producer_packets


def test_summary_is_not_an_invertible_network14_producer(monkeypatch):
    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    from ml.verified_producers.contracts import NETWORK_NAMES
    from ml.verified_producers.network_v1_1 import network_features

    a = producer_packets(request(native=False, tcp=False))
    b = (
        replace(a[0], ip_length=50),
        replace(a[1], timestamp_ns=a[0].timestamp_ns + 100000000),
        replace(a[2], ip_length=70),
    )

    def fields(p):
        return (
            p[-1].timestamp_ns - p[0].timestamp_ns,
            2,
            1,
            p[0].ip_length + p[2].ip_length,
            p[1].ip_length,
        )

    assert fields(a) == fields(b) == (1000000000, 2, 1, 120, 60)
    fa = network_features(a, source_origin="FIXTURE", source_identity="a" * 64)
    fb = network_features(b, source_origin="FIXTURE", source_identity="a" * 64)
    assert fa.values[5:9] != fb.values[5:9] and fa.values[13] != fb.values[13]
    assert tuple(n for n, _, _ in NETWORK14) == NETWORK_NAMES
    assert report()["feature_digest"] is None
    try:
        require_inference()
    except ValueError as e:
        assert "PARITY_BLOCKED" in str(e)
    else:
        raise AssertionError("Ambiguous summary reached inference")
