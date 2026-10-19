"""Approved rate boundaries and controller observations; no network traffic."""

import pytest

from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget
from soc_agent.security_ai.research.backpressure import ObservedRate, QueuePressure


@pytest.mark.parametrize("fps", [64, 128, 256, 512])
def test_virtual_frame_rates_preserve_approved_bucket(fps):
    rate = RateBudget(128, 256, 0)
    consumed = 0
    for i in range(fps * 4):
        try:
            rate.consume(i / fps)
            consumed += 1
        except ValueError as error:
            assert str(error) == "STREAM_RATE_BUDGET_EXCEEDED"
            assert fps > 128
            assert consumed <= 256 + 128 * (i / fps)
            break
    else:
        assert fps <= 128


def test_burst_fractional_refill_and_reversed_clock():
    rate = RateBudget(128, 256, 0)
    for _ in range(256):
        rate.consume(0)
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        rate.consume(0)
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        rate.consume(1 / 256)
    rate.consume(1 / 128)
    assert rate.tokens == 0
    with pytest.raises(ValueError, match="MONOTONIC_CLOCK_REVERSED"):
        rate.consume(0)


def test_native_totals_do_not_identify_burst_trajectory():
    # Same aggregate duration/count can be accepted or rejected depending on
    # arrival timing. Neither synthetic trajectory claims to be Native evidence.
    elapsed = 1.0236316919908859
    assert 256 + 128 * elapsed > 384
    even = RateBudget(128, 256, 0)
    for i in range(384):
        even.consume(elapsed * i / 383)
    late = RateBudget(128, 256, 0)
    for _ in range(256):
        late.consume(elapsed)
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        late.consume(elapsed)


def test_queue_hysteresis_and_overflow_do_not_change_capacity():
    pressure = QueuePressure(8)
    assert pressure.sample(6)["state"] == "HIGH"
    assert pressure.sample(4)["state"] == "HIGH"
    assert pressure.sample(2)["state"] == "NORMAL"
    assert pressure.sample(8)["state"] == "FULL"
    assert pressure.sample(0)["peak"] == 8
    with pytest.raises(ValueError, match="QUEUE_DEPTH_INVALID"):
        pressure.sample(9)


def test_raw_rate_is_unknown_until_two_observations_and_not_wall_clock():
    rate = ObservedRate()
    assert rate.sample(None, 0) is None
    assert rate.sample(100, 2) is None
    assert rate.sample(101, 2) is None  # Equal clock has no measurable rate, not a capture error.
    assert rate.sample(164, 2.5) == 128
    with pytest.raises(ValueError, match="RATE_OBSERVATION_INVALID"):
        rate.sample(163, 3)
