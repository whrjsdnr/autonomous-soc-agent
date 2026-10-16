"""Real unprivileged Unix transport only; helper privilege attestation stays separate."""

import asyncio
import os
import socket
import struct
import types

import pytest

from soc_agent.security_ai.operational.network_capture import helper_transport as transport
from soc_agent.security_ai.operational.network_capture.live_session import prepare
from soc_agent.security_ai.research.live_service import LiveMonitoring, LiveResearch


@pytest.fixture
def observer_only(monkeypatch):
    async def start(self):
        return {"status": "READY"}

    monkeypatch.setattr(LiveResearch, "start", start)


def client_for(session):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(1)
    client.connect(session.socket_address)
    return client


def refused(session):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(1)
        with pytest.raises(ConnectionRefusedError):
            client.connect(session.socket_address)


@pytest.mark.asyncio
async def test_listener_wait_survives_authentication_clock_jump(tmp_path, monkeypatch):
    directory = tmp_path / "session"
    session = prepare(directory)
    capture = transport.HelperCapture(directory, session)
    now = [0]
    monkeypatch.setattr(transport, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    peers = []

    def ordinary_client(channel, ready, session, directory):
        # This substitutes only the raw-socket/capability attestation. No capture
        # helper is launched and this test cannot establish capture readiness.
        peers.append(
            struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        )

    monkeypatch.setattr(transport, "validate_peer", ordinary_client)
    task = asyncio.create_task(asyncio.to_thread(capture.handshake))
    try:
        assert capture.listener_ready()
        assert (directory.stat().st_mode & 0o777) == 0o700
        assert session.socket_address.startswith("\0soc-live-")
        assert "@soc-live-" + str(session.session_id) in open("/proc/net/unix").read()
        await asyncio.sleep(0.05)
        now[0] = 10000
        await asyncio.sleep(0.3)  # Exceeds one accept timeout; no readiness assumed from sleep.
        assert not task.done() and capture.listener_ready()
        with client_for(session) as client:
            client.send(
                transport.Message(
                    kind="READY",
                    session_id=session.session_id,
                    kernel_packets=0,
                    capture_drops=0,
                    counter_sequence=1,
                    counter_status="COUNTER_VERIFIED",
                    kernel_packets_total=0,
                    capture_drops_total=0,
                )
                .model_dump_json()
                .encode()
            )
            await asyncio.wait_for(task, 2)
            assert capture.ready and not capture.listener_ready()
            assert peers == [(os.getpid(), os.getuid(), os.getgid())]
            refused(session)  # Single connection, no second helper queued.
            capture.close()
            assert client.recv(100) == b"STOP"
    finally:
        capture.close()
        await asyncio.gather(task, return_exceptions=True)
    assert not capture.is_live()
    refused(session)


@pytest.mark.asyncio
async def test_prepare_owns_task_until_stop_and_new_session(tmp_path, observer_only):
    service = LiveMonitoring(tmp_path)
    first = await service.start()
    old = service.session
    try:
        assert first["listener_ready"] and service.capture.listener_ready()
        await asyncio.sleep(0.05)
        assert service.task and not service.task.done()
        assert service.handshake_task and not service.handshake_task.done()
        assert service.snapshot()["listener_ready"]
        assert not service.snapshot()["collection_live"]
        with pytest.raises(ValueError, match="ALREADY_ACTIVE"):
            await service.start()
        await asyncio.wait_for(service.stop(), 2)
        assert service.task.done() and service.handshake_task.done()
        assert not service.snapshot()["listener_ready"]
        assert "command" not in service.helper_command(first["session_id"])
        refused(old)
        second = await service.start()
        assert second["listener_ready"] and second["session_id"] != first["session_id"]
        assert service.helper_command(first["session_id"])["status"] == "BLOCKED"
        refused(old)
        assert service.snapshot()["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
        assert service.snapshot()["write_policy"] == "WRITE_DENIED"
        assert not service.snapshot()["research"]["records"]
    finally:
        await service.stop()
        await service.stop()
    restored = LiveMonitoring(tmp_path)
    assert not restored.snapshot()["listener_ready"]
    assert "command" not in restored.helper_command(second["session_id"])
    assert (service.directory / "runtime/monitor.sqlite").exists()


@pytest.mark.asyncio
async def test_listener_unexpected_close_revokes_command_and_reports_error(tmp_path, observer_only):
    service = LiveMonitoring(tmp_path)
    plan = await service.start()
    try:
        await asyncio.sleep(0.05)
        service.capture.listener.close()  # Isolated fault injection.
        assert service.helper_command(plan["session_id"])["status"] == "BLOCKED"
        assert not service.snapshot()["listener_ready"]
        await asyncio.wait_for(service.task, 2)
        result = service.snapshot()
        assert result["state"] == "ERROR"
        assert result["last_error"] == "LIVE_LISTENER_CLOSED_STOP_AND_PREPARE_NEW_SESSION"
        assert service.handshake_task.done()
        refused(service.session)
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_invalid_client_handshake_fails_closed_without_capture(tmp_path, observer_only):
    service = LiveMonitoring(tmp_path)
    plan = await service.start()
    try:
        with client_for(service.session) as client:
            client.send(b'{"kind":"READY","session_id":"invalid"}')
            await asyncio.wait_for(service.task, 3)
        assert not service.capture.listener_ready()
        assert service.snapshot()["state"] == "ERROR"
        assert "HANDSHAKE_FAILED" in service.snapshot()["last_error"]
        assert service.capture.ready is None
        assert not (service.directory / "verified-ready.json").exists()
        assert service.helper_command(plan["session_id"])["status"] == "BLOCKED"
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_stop_during_connected_client_handshake_joins_thread(tmp_path, observer_only):
    service = LiveMonitoring(tmp_path)
    await service.start()
    with client_for(service.session):
        try:
            for _ in range(100):
                if service.capture.channel is not None:
                    break
                await asyncio.sleep(0.01)
            assert service.capture.channel is not None
            await asyncio.wait_for(service.stop(), 2)
            assert service.task.done() and service.handshake_task.done()
            assert service.capture.ready is None
        finally:
            await service.stop()
    refused(service.session)


@pytest.mark.asyncio
async def test_bind_failure_returns_no_command(tmp_path, monkeypatch, observer_only):
    def failed(*args):
        raise OSError("synthetic bind failure")

    monkeypatch.setattr("soc_agent.security_ai.research.live_service.HelperCapture", failed)
    service = LiveMonitoring(tmp_path)
    result = await service.start()
    assert result["status"] == "ERROR" and not result["listener_ready"]
    assert "command" not in result
    assert "PREPARE_FAILED" in service.snapshot()["last_error"]


def test_duplicate_bind_does_not_replace_listener(tmp_path):
    directory = tmp_path / "session"
    session = prepare(directory)
    capture = transport.HelperCapture(directory, session)
    try:
        with pytest.raises(OSError):
            transport.HelperCapture(directory, session)
        assert capture.listener_ready()
        with client_for(session):
            assert capture.listener_ready()
    finally:
        capture.close()
