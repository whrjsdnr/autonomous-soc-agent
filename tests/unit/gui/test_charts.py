"""Measured history, bounded storage, missing-data gaps, no random telemetry."""

import pytest

from soc_agent.gui.charts import MetricHistory


def values(queue=0, completed=0):
    return {
        "queue_backlog": queue,
        "completed_read_only": completed,
        "completed_llm": 0,
        "completed_scripted": 0,
    }


def test_real_values_and_bounded_history():
    history = MetricHistory(capacity=3)
    for i, q in enumerate((0, 4, 2, 0)):
        history.observe(values(q, i), now=float(i))
    assert [s.queue for s in history.samples] == [4, 2, 0]
    assert [s.completed for s in history.samples] == [1, 2, 3]


@pytest.mark.parametrize("invalid", [None, True, -1, float("nan"), "4"])
def test_missing_or_invalid_is_gap_not_zero(invalid):
    history = MetricHistory()
    history.observe(values(invalid), now=1)
    assert history.samples[-1].queue is None


def test_offline_is_unknown_and_does_not_fabricate_completed():
    history = MetricHistory()
    history.observe({"runtime_state": "OFFLINE"}, now=1)
    assert history.samples[-1].queue is None and history.samples[-1].completed is None


def test_time_and_capacity_validation():
    with pytest.raises(ValueError):
        MetricHistory(1)
    history = MetricHistory()
    history.observe(values(), now=4)
    with pytest.raises(ValueError):
        history.observe(values(), now=3)
