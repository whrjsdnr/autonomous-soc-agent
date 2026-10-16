"""Deterministic GUI preparation race: an older STOPPED poll preceded READY."""

from pathlib import Path
from unittest.mock import Mock

from soc_agent.gui.live_view import LiveView
from soc_agent.security_ai.research.stream_service import StreamingMonitoring


def test_ready_reply_disables_start_after_prior_stopped_poll():
    view = object.__new__(LiveView)
    view.observation_started_ns = 100
    view.headline = Mock()
    view.headline.get.return_value = "STOPPED"
    view.instructions = Mock()
    view.instructions.winfo_exists.return_value = True
    view.copy_button = Mock()
    view.start_button = Mock()  # Earlier render(STOPPED) restored normal state.
    view.prepared(
        {
            "listener_ready": True,
            "command": "MOCK_ONLY",
            "session_id": "fixture",
            "observation_started_ns": 200,
        }
    )
    view.start_button.configure.assert_called_with(state="disabled")
    assert view.command == "MOCK_ONLY"


def test_backend_marks_async_preparation_active_before_task_exists(tmp_path: Path):
    owner = StreamingMonitoring(tmp_path)
    owner.preparing = True
    state = owner.snapshot()
    assert owner.task is None
    assert state["prepare_active"]
    assert not state["collection_live"] and not state["listener_ready"]
