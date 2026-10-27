"""Passive measurements never grant Capture or prove an idle Flow."""

import pytest

from soc_agent.security_ai.ebpf_tc.capture_readiness import assess_loopback_budget


def samples(packets=350):
    return [
        dict(namespace="net:[4026531833]", monotonic_ns=1, rx_packets=100, rx_dropped=0),
        dict(
            namespace="net:[4026531833]",
            monotonic_ns=35_000_000_001,
            rx_packets=100 + packets,
            rx_dropped=0,
        ),
    ]


@pytest.mark.parametrize(
    "packets,state",
    [
        (0, "CONDITIONAL_MEASUREMENT_ONLY"),
        (350, "CONDITIONAL_MEASUREMENT_ONLY"),
        (12000, "AMBIENT_RATE_EXCEEDS_BUDGET"),
    ],
)
def test_measured_rate_is_projection_never_execution_authority(packets, state):
    result = assess_loopback_budget(samples(packets))
    assert result["state"] == state
    assert result["projected_45s_packets_mean"] == packets / 35 * 45
    assert result["execution_ready"] is False
    assert result["scenario_packets"] == "NOT_BOUNDED_BY_PASSIVE_MEASUREMENT"


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "other"),
        ("monotonic_ns", 0),
        ("rx_packets", 1),
        ("rx_dropped", -1),
        ("rx_packets", True),
    ],
)
def test_missing_reset_or_wrong_scope_stays_unknown(field, value):
    rows = samples()
    rows[-1][field] = value
    assert assess_loopback_budget(rows)["state"] == "UNKNOWN"


def test_missing_samples_and_burst_average_do_not_hide_peak():
    assert assess_loopback_budget([])["state"] == "UNKNOWN"
    rows = samples(0)
    rows.append(
        dict(
            namespace="net:[4026531833]", monotonic_ns=36_000_000_001, rx_packets=300, rx_dropped=0
        )
    )
    result = assess_loopback_budget(rows)
    assert result["packet_rate_mean"] < 4096 / 45
    assert result["state"] == "AMBIENT_RATE_EXCEEDS_BUDGET"


def test_short_quiet_sample_and_bad_shape_do_not_claim_sufficient_observation():
    rows = samples(0)
    rows[-1]["monotonic_ns"] = 1_000_000_001
    assert assess_loopback_budget(rows)["state"] == "UNKNOWN_SHORT_OBSERVATION"
    assert assess_loopback_budget([None, {}])["state"] == "UNKNOWN"
