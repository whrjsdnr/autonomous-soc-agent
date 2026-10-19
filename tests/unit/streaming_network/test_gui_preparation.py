"""Controller callbacks: no Tk display, capture, credentials, or authentication child."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from soc_agent.gui.live_view import LiveView, preparation_message


def view():
    result = object.__new__(LiveView)
    result.total = result.streaming = True
    result.prefix, result.page = "total", "Total Monitoring"
    result.observation_started_ns = 0
    result.command, result.command_session = "", None
    result.headline = Mock()
    result.headline.get.return_value = "STOPPED"
    result.instructions = Mock()
    result.instructions.winfo_exists.return_value = True
    result.copy_button, result.start_button = Mock(), Mock()
    result.app = SimpleNamespace(
        page=result.page,
        notice=Mock(),
        call=Mock(),
        config=SimpleNamespace(total_approved_sha="a" * 64, total_rate_policy="balanced-v2"),
    )
    return result


def ready(stamp=100):
    return dict(
        listener_ready=True,
        command="MOCK_ONLY",
        session_id="fixture-session",
        helper_sha256="a" * 64,
        policy_name="balanced-v2",
        observation_started_ns=stamp,
        authentication="Use your terminal; no password in GUI.",
    )


@pytest.mark.parametrize(
    "payload,expected",
    [
        (
            {
                "authentication": "Use terminal",
                "last_error": "FIRST_ERROR",
                "error": "SECOND_ERROR",
            },
            "Use terminal",
        ),
        ({"last_error": "FIRST_ERROR", "error": "SECOND_ERROR"}, "FIRST_ERROR"),
        ({"error": "SECOND_ERROR"}, "SECOND_ERROR"),
        ({"last_error": "STREAM_FAILURE:42"}, "STREAM_FAILURE:42"),
        ({}, "Environment unavailable"),
        ({"authentication": None, "last_error": 42, "error": "SECOND_ERROR"}, "SECOND_ERROR"),
        ({"authentication": "x" * 513, "last_error": "FIRST_ERROR"}, "FIRST_ERROR"),
        ({"last_error": "private/path/secret"}, "Environment unavailable"),
        ({"error": "x" * 4096}, "Environment unavailable"),
    ],
)
def test_blocked_reply_priority_types_bounds_and_controls(payload, expected):
    item = view()
    item.prepared(ready())
    item.app.call.reset_mock()
    result = dict(payload, status="BLOCKED", listener_ready=False, observation_started_ns=200)
    item.started(result)
    text = item.instructions.insert.call_args.args[1]
    assert expected in text and "NOT_PREPARED" in text and "No capture started" in text
    assert "LISTENER READY" not in item.headline.set.call_args.args[0]
    assert item.command == "" and item.command_session is None
    item.copy_button.configure.assert_called_with(state="disabled")
    item.start_button.configure.assert_called_with(state="normal")
    item.app.call.assert_not_called()
    item.request_authentication(result)
    item.app.call.assert_not_called()
    assert "private/path/secret" not in text


def test_ready_path_preserves_copy_and_explicit_approved_scope():
    item = view()
    item.started(ready())
    assert item.command == "MOCK_ONLY" and item.command_session == "fixture-session"
    item.copy_button.configure.assert_called_with(state="normal")
    item.start_button.configure.assert_called_with(state="disabled")
    assert "LISTENER READY" in item.headline.set.call_args.args[0]
    assert "a" * 64 in item.instructions.insert.call_args.args[1]
    assert item.app.call.call_args.args == ("total_authenticate", "fixture-session", "a" * 64)


def test_stale_ready_callback_and_poll_cannot_override_failure_or_authenticate():
    item = view()
    blocked = dict(
        listener_ready=False,
        status="BLOCKED",
        last_error="STREAM_ARCHIVAL_REQUIRED",
        observation_started_ns=200,
    )
    item.started(blocked)
    calls = item.copy_button.configure.call_count
    item.started(ready(100))
    item.render(
        dict(state="AUTHENTICATION_REQUIRED", listener_ready=True, observation_started_ns=100)
    )
    assert item.copy_button.configure.call_count == calls
    assert "STREAM_ARCHIVAL_REQUIRED" in item.headline.set.call_args.args[0]
    assert not item.command
    item.app.call.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [("helper_sha256", None), ("helper_sha256", 42), ("command", None), ("session_id", None)],
)
def test_incomplete_ready_response_cannot_request_authentication(field, value):
    item = view()
    result = ready()
    result[field] = value
    item.started(result)
    assert not item.command
    assert "NOT_PREPARED" in item.headline.set.call_args.args[0]
    item.app.call.assert_not_called()


def test_control_characters_are_not_forwarded_as_messages():
    assert (
        preparation_message(dict(authentication="bad\x00message", last_error="SAFE_ERROR"))
        == "SAFE_ERROR"
    )
