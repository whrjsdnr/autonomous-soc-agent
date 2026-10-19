"""Identical OUTBOUND scope, preserved timestamps, independent PCAP/hand reference."""

import pytest
from tests.unit.live_network.test_parity import request
from tests.unit.live_network.test_parity import (
    test_wire_parsers_origins_and_independent_hand_reference as golden,
)

from soc_agent.security_ai.operational.network_capture.direction_policy import (
    Accounting,
    DirectionPolicy,
)
from soc_agent.security_ai.research.live_input import produce


@pytest.mark.parametrize("tcp,ipv6", [(True, False), (False, False), (True, True), (False, True)])
def test_direction_filter_feature_golden_pair(monkeypatch, tcp, ipv6):
    from tests.research_adapter_support import research_paths

    paths = research_paths()
    monkeypatch.syspath_prepend(str((paths.producer_source or paths.ml) / "src"))
    r = request(ipv6=ipv6, tcp=tcp)
    a = Accounting(DirectionPolicy(), 0)
    selected = []
    for i, packet in enumerate(r.packets):
        for direction in ("OUTBOUND", "INBOUND"):
            if a.admit(direction, i / 10):
                selected.append(packet)
                a.normalized += 1
    filtered = r.model_copy(update={"packets": tuple(selected)})
    assert produce(filtered) == produce(r)
    golden(ipv6, tcp)
    assert a.raw == 6 and a.filtered == 3 and a.normalized == 3
