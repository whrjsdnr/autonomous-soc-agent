"""Keep timing evidence paired without changing execution or timeout contracts."""

from collections import deque
from types import SimpleNamespace

import pytest
from tests.unit.continuous.test_storage_control_isolation import runtime

from soc_agent.continuous import service as runtime_service
from soc_agent.continuous.native import service as root_service


@pytest.mark.asyncio
async def test_maximum_keeps_its_own_interval_after_a_shorter_operation(tmp_path, monkeypatch):
    _, value = runtime(tmp_path)
    samples = iter([10.0, 22.5, 23.0, 23.5])
    monkeypatch.setattr(runtime_service, "time", SimpleNamespace(monotonic=lambda: next(samples)))

    def first_update():
        return "first"

    def later_counts():
        return "later"

    assert await value.storage(first_update) == "first"
    assert await value.storage(later_counts) == "later"
    health = value.storage_health
    assert health["operation"] == "later_counts"
    assert health["started_monotonic"] == 23.0
    assert health["completed_monotonic"] == 23.5
    assert health["last_seconds"] == 0.5
    assert health["max_operation"] == "first_update"
    assert health["max_started_monotonic"] == 10.0
    assert health["max_completed_monotonic"] == 22.5
    assert health["max_seconds"] == 12.5


@pytest.mark.asyncio
async def test_failed_storage_preserves_its_interval_without_claiming_success(
    tmp_path, monkeypatch
):
    _, value = runtime(tmp_path)
    samples = iter([10.0, 22.5])
    monkeypatch.setattr(runtime_service, "time", SimpleNamespace(monotonic=lambda: next(samples)))

    def failing_update():
        raise OSError("injected storage failure")

    with pytest.raises(OSError, match="injected storage failure"):
        await value.storage(failing_update)
    health = value.storage_health
    assert not health["pending"]
    assert health["max_operation"] == "failing_update"
    assert health["max_started_monotonic"] == 10.0
    assert health["max_completed_monotonic"] == 22.5
    assert health["max_seconds"] == 12.5
    assert value.last_error is None  # This wrapper must propagate, not classify/overwrite.


def test_post_send_diagnostic_completion_is_distinct_from_send_completion(monkeypatch):
    samples = iter([10, 20, 40])
    monkeypatch.setattr(
        root_service,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: next(samples), process_time_ns=lambda: 1, thread_time_ns=lambda: 2
        ),
    )
    monkeypatch.setattr(
        root_service, "socket_diagnostics", lambda peer: {"observed_monotonic_ns": 25}
    )
    value = object.__new__(root_service.ControlTransport)
    value.peer = SimpleNamespace(send=len)
    value.trace = deque(maxlen=64)
    value.trace_total = 0
    value.send_totals = dict(SENT=0, PARTIAL=0, BACKPRESSURE=0, ERROR=0)
    assert value.emit(b"fixture", "CONTROL", 1, 1, 2) == 7
    row = value.trace[0]
    assert row["outcome"] == "SENT"
    assert row["send_started_ns"] == 10
    assert row["send_completed_ns"] == 20
    assert row["socket"]["observed_monotonic_ns"] == 25
    assert row["post_send_diagnostics_completed_ns"] == 40
    assert value.previous_control_send == row
