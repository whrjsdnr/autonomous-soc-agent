"""Bounded arithmetic and isolation assessment; no privileged/capture/traffic operation."""

import hashlib
import json
import os
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.live_flow_eligibility_support import BASE_NS
from tests.native_idle_budget_support import assessment, projected_frames
from tests.research_adapter_support import research_paths
from tests.unit.live_network.test_parity import observation, wire

from soc_agent.security_ai.operational.network_capture import live_session
from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig
from soc_agent.security_ai.research.models import SPECS, digest


def test_projection_hand_arithmetic_not_a_future_guarantee():
    # Independent integer reference: 512 / 8 = 64 frames/s.
    assert projected_frames(512, 8, 31) == 2000  # 64*31 +16
    assert projected_frames(512, 8, 31, safety=1.5) == 2992
    assert projected_frames(512, 8, 31, extra=0) == 1984
    assert projected_frames(1, 3, 1, extra=0) == 1  # Always round up.


@pytest.mark.parametrize(
    "frames,elapsed,seconds,extra,safety",
    [
        (None, 8, 31, 16, 1),
        (0, 8, 31, 16, 1),
        (True, 8, 31, 16, 1),
        (512, None, 31, 16, 1),
        (512, 0, 31, 16, 1),
        (512, float("nan"), 31, 16, 1),
        (512, 8, float("inf"), 16, 1),
        (512, 8, 31, -1, 1),
        (512, 8, 31, 16, 0.9),
    ],
)
def test_unknown_and_invalid_budget_never_become_zero(frames, elapsed, seconds, extra, safety):
    with pytest.raises(ValueError, match="UNKNOWN_OR_INVALID"):
        projected_frames(frames, elapsed, seconds, extra=extra, safety=safety)


def test_frame_bound_hit_before_idle_in_synthetic_clone_budget():
    table = FlowTable(CaptureConfig(interface="lo"))
    completed = []
    # Synthetic two-clone assumption only: 256 metadata observations use 512 frames.
    for i in range(256):
        packet = observation(wire(), BASE_NS + i * 36_000_000, native=False)
        completed.extend(table.add(packet, str(i)))
    completed.extend(table.expire(packet.timestamp, "SHUTDOWN"))
    assert packet.timestamp - observation(wire(), BASE_NS, native=False).timestamp < timedelta(
        seconds=10
    )
    assert not any(f.close_reason in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"} for f in completed)
    assert sum(len(f.source_event_ids) for f in completed) == 256


def test_waiting_does_not_move_delivered_packet_watermark_but_sentinel_does():
    table = FlowTable(CaptureConfig(interface="lo"))
    last = None
    for i, t in enumerate((0, 0.5, 1)):
        last = observation(wire(tcp=False), BASE_NS + int(t * 1e9), native=False)
        assert not table.add(last, str(i))
    capture = object.__new__(HelperCapture)  # No __init__, no socket or thread created.
    capture.reader_lock = threading.RLock()
    capture.reader_thread = object()
    capture.last_delivered_at = last.timestamp
    assert not table.expire(capture.flow_watermark(last.timestamp + timedelta(seconds=31)))
    body = bytearray(wire(tcp=False))
    body[34:36] = (1001).to_bytes(2, "big")
    sentinel = observation(bytes(body), BASE_NS + 32_000_000_000, native=False)
    ended = table.add(sentinel, "sentinel")
    assert len(ended) == 1 and ended[0].close_reason == "IDLE_TIMEOUT"
    assert ended[0].forward_packets == 3 and ended[0].backward_packets == 0


def test_current_approved_bounds_cannot_be_raised_by_session_json(tmp_path):
    session = live_session.prepare(tmp_path / "session")
    assert session.socket_address.startswith("\0soc-live-")  # Abstract, no filesystem socket.
    for field, value in (("max_packets", 513), ("seconds", 61), ("interface", "veth0")):
        with pytest.raises(ValidationError):
            live_session.Session.model_validate({**session.model_dump(), field: value})
    with pytest.raises(ValidationError):
        Message(kind="CLOSED", session_id=session.session_id, received_frames=513)


def test_namespace_change_rejects_existing_interface_session(tmp_path, monkeypatch):
    from soc_agent.security_ai.operational.network_capture import capture

    directory = tmp_path / "session"
    session = live_session.prepare(directory)
    original = capture.os.stat
    inode = original("/proc/self/ns/net").st_ino

    def changed(path, *args, **kwargs):
        if str(path) == "/proc/self/ns/net":
            from types import SimpleNamespace

            return SimpleNamespace(st_ino=inode + 1)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(capture.os, "stat", changed)
    assert capture.interface_identity("lo") != session.interface_id
    with pytest.raises(ValueError, match="INTERFACE_CHANGED"):
        live_session.load_session(directory)


def test_approved_helper_and_existing_artifacts_unchanged():
    helper = Path(live_session.__file__).with_name("live_helper.py")
    assert (
        hashlib.sha256(helper.read_bytes()).hexdigest()
        == "a8a0cafe7494922a0296a250129ab5695b681dbbec6febf512509b023ef44856"
    )
    for spec in SPECS.values():
        path = (
            research_paths().ml
            / "models/network-research-v1-final"
            / spec["directory"]
            / "model.joblib"
        )
        assert hashlib.sha256(path.read_bytes()).hexdigest() == spec["sha256"]


def test_retained_session_assessment_matches_sanitized_evidence():
    requested = os.environ.get("SOC_IDLE_BUDGET_SESSION")
    if not requested:
        pytest.skip("Explicit read-only retained-session opt-in required")
    root = Path(requested).absolute()
    before = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }
    result = assessment(root)
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "docs/linux-soc-v1/native-idle-flow-budget-evidence.json"
        ).read_text()
    )
    claimed = manifest.pop("evidence_digest")
    assert digest(manifest) == claimed
    assert result == manifest["retained_session"]
    assert result["received_frames"] == 512 and result["stored_packets"] == 256
    assert result["queue"] == {"DONE": 260} and result["model_receipts"] == 0
    assert result["frame_budget"] == "FRAME_BUDGET_INSUFFICIENT"
    assert sum(f["packets"] for f in result["flows"]) == 256
    assert max(f["max_interpacket_seconds"] for f in result["flows"]) < 30
    after = {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*")
        if p.is_file()
    }
    assert before == after
