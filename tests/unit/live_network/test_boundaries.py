"""No capture/elevation. Linux socket/process observations are mocked for rejection cases."""

import asyncio
import json
import os
import shlex
import socket
from uuid import uuid4

import pytest

from soc_agent.gui.live_view import display_state
from soc_agent.security_ai.operational.network_capture.helper_transport import (
    HelperCapture,
    Message,
    validate_peer,
)
from soc_agent.security_ai.operational.network_capture.live_helper import check_privileges
from soc_agent.security_ai.operational.network_capture.live_session import (
    instructions,
    load_session,
    prepare,
)
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.live_service import LiveMonitoring


def test_unprivileged_helper_rejected_before_any_socket(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("CAPTURE_MUST_NOT_OPEN")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ValueError, match="CAP_NET_RAW"):
        check_privileges()


def test_plan_is_text_only_fixed_interface_and_bounds(tmp_path):
    root = tmp_path / "session"
    s = prepare(root)
    plan = instructions(root, s)
    parts = shlex.split(plan["command"])
    assert parts[:4] == ["sudo", "-n", "/usr/bin/setpriv", f"--reuid={os.getuid()}"]
    assert "--bounding-set=-all,+net_raw" in parts and "--ambient-caps=-all,+net_raw" in parts
    assert "-S" not in parts and "--no-new-privs" in parts
    assert plan["seconds"] == 60 and plan["packet_limit"] == 512 and plan["interface"] == "lo"
    assert load_session(root) == s
    with pytest.raises(ValueError):
        prepare(tmp_path / "over", seconds=61)


@pytest.mark.parametrize("tamper", ["code", "interface", "identity"])
def test_session_mutation_fails_closed(tmp_path, tamper):
    root = tmp_path / "session"
    prepare(root)
    p = root / "session.json"
    v = json.loads(p.read_text())
    if tamper == "code":
        v["code_sha256"]["live_helper.py"] = "0" * 64
    if tamper == "interface":
        v["interface"] = "eth0"
    if tamper == "identity":
        v["uid"] += 1
    p.write_text(json.dumps(v))
    with pytest.raises(ValueError):
        load_session(root)


def test_session_symlink_rejected(tmp_path):
    root = tmp_path / "session"
    prepare(root)
    (tmp_path / "link").symlink_to(root, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        load_session(tmp_path / "link")


def test_oversized_payload_unknown_fields_rejected():
    with pytest.raises(ValueError):
        Message(kind="PACKET", session_id=uuid4(), raw_payload="x")


def test_live_label_requires_actual_helper():
    assert (
        display_state({"state": "LIVE_RESEARCH_INFERENCE", "collection_live": False}) == "UNKNOWN"
    )
    assert (
        display_state({"state": "RETAINED_SESSION_NOT_LIVE", "collection_live": False})
        == "RETAINED_SESSION_NOT_LIVE"
    )


@pytest.mark.asyncio
async def test_native_request_without_source_authority_is_blocked(tmp_path):
    from tests.unit.live_network.test_parity import request

    adapter = ResearchAdapter(tmp_path, live_metadata=True)
    result = await adapter.infer(request())
    assert result == {"status": "UNKNOWN", "error": "NATIVE_CAPTURE_SOURCE_NOT_VERIFIED"}
    assert adapter.process is None


@pytest.mark.asyncio
async def test_wait_stop_duplicate_start_and_no_live_recovery(tmp_path):
    service = LiveMonitoring(tmp_path)
    plan = await service.start(seconds=1)
    assert plan["command"] and service.snapshot()["collection_live"] is False
    assert service.snapshot()["state"] == "AUTHENTICATION_REQUIRED"
    with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
        await service.start()
    await service.stop()
    assert service.task.done()
    restored = LiveMonitoring(tmp_path)
    assert restored.snapshot()["state"] == "RETAINED_SESSION_NOT_LIVE"
    assert not restored.snapshot()["collection_live"]
    assert not restored.snapshot()["research"]["records"]


def test_protocol_sequence_and_forgery(tmp_path, monkeypatch, request_fixture):
    s = prepare(tmp_path / "session")
    capture = HelperCapture(tmp_path / "session", s)
    try:
        capture.alive = True
        monkeypatch.setattr(
            capture,
            "message",
            lambda: Message(
                kind="PACKET",
                session_id=s.session_id,
                sequence=2,
                packet=request_fixture.packets[0],
            ),
        )
        with pytest.raises(ValueError, match="BINDING"):
            capture.receive()
    finally:
        capture.close()


def test_foreign_uid_cannot_supply_ready(tmp_path):
    import struct

    s = prepare(tmp_path / "session")

    class Foreign:
        def getsockopt(self, *args):
            return struct.pack("3i", 12345, s.uid + 1, s.gid)

    ready = Message(kind="READY", session_id=s.session_id, pid=12345)
    with pytest.raises(ValueError, match="PEER_MISMATCH"):
        validate_peer(Foreign(), ready, s, tmp_path / "session")


def test_model_queue_overflow_is_explicit(tmp_path):
    from soc_agent.realtime.queue import QueueFull

    service = LiveMonitoring(tmp_path)

    class Flow:
        close_reason = "IDLE_TIMEOUT"

    for _ in range(8):
        service.on_flow(None, Flow(), None)
    with pytest.raises(QueueFull):
        service.on_flow(None, Flow(), None)


@pytest.mark.asyncio
async def test_concurrent_prepare_and_cancel_are_bounded(tmp_path):
    service = LiveMonitoring(tmp_path)
    preparing = asyncio.create_task(service.start())
    await asyncio.sleep(0)
    with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
        await service.start()
    await service.stop()
    assert (await preparing)["status"] == "STOPPED"
    assert service.task is None
    assert service.snapshot()["collection_live"] is False


def test_saved_evidence_verifier_missing_primary_data_fails_closed(tmp_path):
    from soc_agent.security_ai.research.live_evidence import verify

    prepare(tmp_path / "session")
    with pytest.raises((ValueError, OSError)):
        verify(tmp_path / "session")


def test_invalid_retained_session_does_not_start_or_block_entire_gui(tmp_path):
    from soc_agent.review.persistence.secure_storage import create_private_directory

    create_private_directory(tmp_path / "live-network")
    root = tmp_path / "live-network/session-invalid"
    prepare(root)
    path = root / "session.json"
    value = json.loads(path.read_text())
    value["code_sha256"]["live_helper.py"] = "0" * 64
    path.write_text(json.dumps(value))
    service = LiveMonitoring(tmp_path)
    snapshot = service.snapshot()
    assert snapshot["state"] == "UNKNOWN" and snapshot["collection_live"] is False
    assert service.task is None and service.capture is None
    assert json.loads(path.read_text()) == value  # No repair or evidence replacement.
