import json
import os

import pytest

from soc_agent.security_ai.operational.network_capture.stream_session import (
    RateBudget,
    StreamPolicy,
    instructions,
    load,
    prepare,
)


@pytest.mark.parametrize(
    "change",
    [
        {"seconds": 0},
        {"seconds": 1801},
        {"interface": "eth0"},
        {"frames_per_second": 129},
        {"burst_frames": 257},
        {"transport_capacity": 513},
        {"inference_capacity": 9},
        {"metadata_bytes": 17 * 1024**2},
        {"max_inferences": 257},
        {"dns_headers": "yes"},
    ],
)
def test_policy_bounded(change):
    with pytest.raises(ValueError):
        StreamPolicy(**change)


def test_rate_budget_stops_without_silent_drop_or_retry():
    rate = RateBudget(2, 2, 0)
    rate.consume(0)
    rate.consume(0)
    with pytest.raises(ValueError, match="RATE_BUDGET"):
        rate.consume(0.1)
    rate.consume(0.5)
    with pytest.raises(ValueError, match="CLOCK_REVERSED"):
        rate.consume(0.4)


def test_separate_helper_identity_private_session_and_exact_command(tmp_path):
    path = tmp_path / "session"
    session = prepare(path, StreamPolicy())
    assert session.max_packets == 38656
    assert session.uid == os.getuid() > 0
    assert load(path) == session
    assert path.stat().st_mode & 0o777 == 0o700
    assert (path / "session.json").stat().st_mode & 0o777 == 0o600
    command = instructions(path, session)
    assert command["status"] == "NEW_HELPER_USER_APPROVAL_REQUIRED"
    assert "stream_helper" in command["command"]
    assert "--no-new-privs" in command["command"]
    assert "password" not in json.dumps(session.model_dump(mode="json")).lower()
    data = json.loads((path / "session.json").read_text())
    data["code_sha256"]["stream_helper.py"] = "f" * 64
    (path / "session.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="IDENTITY"):
        load(path)
