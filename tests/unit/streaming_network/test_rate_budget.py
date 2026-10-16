"""No capture: compare the approved bucket with exact rational arithmetic."""

from fractions import Fraction

import pytest

from soc_agent.security_ai.operational.network_capture.stream_session import RateBudget


@pytest.mark.parametrize("fps", [128, 129, 256, 1000])
def test_rate_decisions_match_independent_rational_reference(fps):
    start = 3090000.0
    bucket = RateBudget(128, 256, start)
    tokens, previous = Fraction(256), Fraction.from_float(start)
    rejected = False
    for n in range(38656):
        now = start + n / fps
        exact = Fraction.from_float(now)
        tokens = min(Fraction(256), tokens + (exact - previous) * 128)
        previous = exact
        if tokens < 1:
            with pytest.raises(ValueError, match="^STREAM_RATE_BUDGET_EXCEEDED$"):
                bucket.consume(now)
            rejected = True
            break
        bucket.consume(now)
        tokens -= 1
        assert bucket.tokens == float(tokens)
    assert rejected == (fps > 128)


def test_burst_boundary_equal_clock_fractional_refill_and_cap():
    bucket = RateBudget(128, 256, 1.0)
    for _ in range(256):
        bucket.consume(1.0)
    assert bucket.tokens == 0
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        bucket.consume(1.0)  # 257th raw frame, even if loopback clone/filtered.
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        bucket.consume(1 + 1 / 256)
    assert bucket.tokens == 0.5
    bucket.consume(1 + 1 / 128)
    assert bucket.tokens == 0
    bucket.consume(300.0)  # Backpressure/deadline delay cannot accumulate > burst.
    assert bucket.tokens == 255
    with pytest.raises(ValueError, match="MONOTONIC_CLOCK_REVERSED"):
        bucket.consume(299.0)


def test_total_frame_guard_is_separate_from_rate_bucket():
    # Exactly 256 initial + 128/s for 300 seconds; no off-by-one in the bucket.
    bucket = RateBudget(128, 256, 0.0)
    for _ in range(256):
        bucket.consume(0.0)
    for n in range(1, 38401):
        bucket.consume(n / 128)
    assert bucket.tokens == 0
    with pytest.raises(ValueError, match="RATE_BUDGET_EXCEEDED"):
        bucket.consume(300.0)
