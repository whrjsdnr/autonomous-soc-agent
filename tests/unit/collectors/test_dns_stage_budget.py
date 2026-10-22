"""Reproduce the 0.6.1 cold-start budget overlap without capture or Root."""

import pytest

from soc_agent.security_ai.collectors.analysis_feed import AnalysisFeed
from soc_agent.security_ai.collectors.live_contract import new_plan
from soc_agent.security_ai.collectors.live_process import StreamProcess
from soc_agent.security_ai.ebpf_tc.dns_copy_engine import capture_deadline


@pytest.mark.parametrize("ready_after", [0.1, 2.4435, 5.0, 8.7])
def test_cold_start_shortens_capture_and_reserves_analysis_and_cleanup(ready_after):
    session_start = 100.0
    end = session_start + 10
    ready = session_start + ready_after
    capture_end = capture_deadline(ready, end, start_gate=True)
    assert 0 < capture_end - ready <= 6.9 + 1e-12
    assert end - 0.5 - capture_end >= 0.75
    assert end - (end - 0.5) == 0.5


def test_native_061_closed_before_analysis_deadline_does_not_prove_process_exit(
    tmp_path, monkeypatch
):
    # Recorded monotonic times: READY 529353.935, CLOSED 529360.934,
    # session start 529351.492. Docker exit followed CLOSED, after the
    # internal 9.5s deadline. The outer 10s deadline was not exceeded.
    start, ready = 529351.491920225, 529353.935443511
    deadline = start + 10
    old_capture_end = min(ready + 6.9, deadline - 0.75)
    assert deadline - 0.5 - old_capture_end == 0.25
    new_capture_end = capture_deadline(ready, deadline, start_gate=True)
    assert old_capture_end - new_capture_end == 0.5
    runner = StreamProcess(
        tmp_path, new_plan(), analysis_feed=AnalysisFeed(), analysis_deadline=deadline - 0.5
    )
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.live_process.time.monotonic", lambda: deadline - 0.5
    )
    # Still fail closed if EOF/exit is late; CLOSED cannot exempt the deadline.
    runner.phase_times["closed"] = deadline - 0.6
    assert runner.deadline_expired()
    with pytest.raises(ValueError, match="DEADLINE_BEFORE_LAUNCH"):
        runner.run()


@pytest.mark.parametrize("ready", [108.75, 109.0, 111.0])
def test_no_remaining_capture_budget_fails_before_ready(ready):
    with pytest.raises(ValueError, match="DNS_COPY_CAPTURE_START_DEADLINE"):
        capture_deadline(ready, 110.0, start_gate=True)


def test_non_start_gated_diagnostic_keeps_existing_capture_bound():
    assert capture_deadline(100, 110, start_gate=False) == 106.9
