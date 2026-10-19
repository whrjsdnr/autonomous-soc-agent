"""Controller-only queue observations; never changes the approved capture policy."""

from dataclasses import dataclass


@dataclass
class QueuePressure:
    capacity: int
    peak: int = 0
    pressured: bool = False

    def __post_init__(self):
        if not 1 <= self.capacity <= 512:
            raise ValueError("STREAM_QUEUE_CAPACITY_INVALID")

    def sample(self, depth: int) -> dict:
        if not 0 <= depth <= self.capacity:
            raise ValueError("STREAM_QUEUE_DEPTH_INVALID")
        high = max(1, (self.capacity * 3 + 3) // 4)
        low = self.capacity // 4
        self.peak = max(self.peak, depth)
        if depth >= high:
            self.pressured = True
        elif depth <= low:
            self.pressured = False
        return dict(
            depth=depth,
            capacity=self.capacity,
            high_watermark=high,
            low_watermark=low,
            peak=self.peak,
            state="FULL" if depth == self.capacity else "HIGH" if self.pressured else "NORMAL",
        )


@dataclass
class ObservedRate:
    """Counter deltas / monotonic observation interval, not packet arrival timing."""

    previous: tuple[int, float] | None = None

    def sample(self, count: int | None, now: float) -> float | None:
        if count is None:
            return None
        previous = self.previous
        if previous is None:
            self.previous = (count, now)
            return None
        delta, elapsed = count - previous[0], now - previous[1]
        if delta < 0 or elapsed < 0:
            raise ValueError("STREAM_RATE_OBSERVATION_INVALID")
        if elapsed == 0:
            return None  # No measurable interval; retain baseline for the next sample.
        self.previous = (count, now)
        return delta / elapsed
