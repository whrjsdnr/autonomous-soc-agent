"""Only private test DBs and socket/proc fixtures; no sudo, raw capture, or traffic."""

import asyncio
import json
import os
import shlex
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.unit.network_capture.test_packets import frame

from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture import manual_capture as manual
from soc_agent.security_ai.operational.network_capture.capture import CaptureUnavailable


def ready(session):
    return manual.Ready(
        session_digest=session.digest,
        pid=os.getpid(),
        process_start=manual.process_start(os.getpid()),
        socket_fd=9,
        socket_inode=123,
        uid=session.uid,
        gid=session.gid,
        interface_id=session.interface_id,
        effective=0,
        permitted=0,
        inheritable=0,
        ambient=0,
        bounding=8192,
        no_new_privs=1,
    )


def test_command_generation_does_not_execute_or_create_a_session(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("No process or network operation allowed in command generation")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(manual.socket, "socket", forbidden)
    root = tmp_path / "manual"
    result = manual.commands(root)
    args = shlex.split(result["terminal_B_user_only_capture"])
    assert args[:3] == ["sudo", "-n", "/usr/bin/setpriv"]
    assert "--bounding-set=-all,+net_raw" in args and "--no-new-privs" in args
    assert "--reuid=" + str(os.getuid()) in args
    assert args[-3:] == ["capture", "--directory", str(root)]
    assert result["approval_required"] and not root.exists()
    assert result["original_probe_unchanged_sha256"] == manual.ORIGINAL_SHA


def test_unprivileged_capture_is_denied_before_any_session_write(tmp_path):
    root = tmp_path / "manual"
    with pytest.raises(CaptureUnavailable, match="NET_RAW_REQUIRED"):
        asyncio.run(manual.capture(root))
    assert not root.exists()


def test_no_ready_never_generates_traffic(tmp_path, monkeypatch):
    clock = iter([0, 121])
    monkeypatch.setattr(manual.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(manual, "loopback_traffic", lambda: pytest.fail("premature traffic"))
    with pytest.raises(ValueError, match="READY_NOT_OBSERVED"):
        manual.watch(tmp_path / "not-started")


@pytest.mark.parametrize("attack", ["session", "uid", "interface", "capability"])
def test_forged_ready_is_rejected_before_traffic(tmp_path, monkeypatch, attack):
    root = tmp_path / "manual"
    session = manual.initialize_session(root)
    value = ready(session).model_dump(mode="json")
    key, wrong = {
        "session": ("session_digest", "a" * 64),
        "uid": ("uid", 999),
        "interface": ("interface_id", "b" * 64),
        "capability": ("effective", 8192),
    }[attack]
    value[key] = wrong
    manual.write_record(root / "ready.json", value)
    monkeypatch.setattr(manual, "loopback_traffic", lambda: pytest.fail("forged READY traffic"))
    with pytest.raises(ValueError, match="READY_SESSION_BINDING"):
        manual.watch(root)
    assert not (root / "traffic-claimed.json").exists()


def test_observer_replay_is_blocked_even_after_a_traffic_failure(tmp_path, monkeypatch):
    root = tmp_path / "manual"
    session = manual.initialize_session(root)
    manual.write_record(root / "ready.json", ready(session).model_dump(mode="json"))
    monkeypatch.setattr(manual, "validate_ready_peer", lambda *args: ready(session))
    calls = []

    def traffic_failure():
        calls.append(True)
        raise TimeoutError("fixture")

    monkeypatch.setattr(manual, "loopback_traffic", traffic_failure)
    with pytest.raises(TimeoutError):
        manual.watch(root)
    with pytest.raises(ValueError, match="REPLAY"):
        manual.watch(root)
    assert calls == [True]


def test_ready_record_publication_is_exclusive_and_digest_checked(tmp_path):
    root = tmp_path / "private"
    manual.create_private_directory(root)
    path = root / "ready.json"
    manual.write_record(path, {"stage": "FIXTURE"})
    with pytest.raises(FileExistsError):
        manual.write_record(path, {"stage": "WRONG"})
    assert manual.read_record(path) == {"stage": "FIXTURE"}
    value = json.loads(path.read_text())
    value["payload"]["stage"] = "TAMPERED"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="DIGEST"):
        manual.read_record(path)


def test_symlink_traversal_and_session_replay_are_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="REDIRECTION"):
        manual.path_checked(alias / "run")
    with pytest.raises(ValueError, match="REDIRECTION"):
        manual.path_checked(tmp_path / ".." / "run")
    root = tmp_path / "session"
    manual.initialize_session(root)
    with pytest.raises(ValueError, match="ALREADY_EXISTS"):
        manual.initialize_session(root)


def test_code_or_interpreter_change_is_not_adopted(tmp_path, monkeypatch):
    root = tmp_path / "manual"
    manual.initialize_session(root)
    monkeypatch.setattr(manual, "code_digests", lambda: ())
    with pytest.raises(ValueError, match="CODE_CHANGED"):
        manual.load_session(root)


def test_socket_fixture_data_persists_and_recovers_without_inference(tmp_path, monkeypatch):
    # The worker gets a fake socket response, not real kernel capture.
    class SocketFixture:
        def __init__(self, config, root, session):
            self.identity = session.interface_id
            self.received = 0
            self.stop = None

        def open(self):
            pass

        def close(self):
            pass

        def receive(self):
            if self.received:
                self.stop.set()
                return None
            self.received += 1
            now = datetime.now(UTC)
            return frame(), now, "OUTBOUND", int(now.timestamp()) * 10**9 + now.microsecond * 1000

        def statistics(self):
            return 1, 0

    monkeypatch.setattr(manual, "validate_probe_privileges", lambda: None)
    monkeypatch.setattr(manual, "ManualCapture", SocketFixture)
    root = tmp_path / "fixture-only"
    result = asyncio.run(manual.capture(root))
    assert result["metrics"]["packets_collected"] == 1
    assert result["metrics"]["inference_count"] == 0
    first = manual.verify(root)
    second = manual.verify(root)
    assert first == second
    assert first["summary"]["queue_counts"] == {"DONE": 2}
    assert first["summary"]["packets"] == first["summary"]["flows"] == 1
    assert first["status"] == "PARTIAL"  # No real READY/peer/traffic evidence.
    assert first["sqlite_integrity"] and first["duplicate_effect_prevented"]
    assert first["write_disposition"] == "WRITE_DENIED"
    assert all(g["inference"] == "BLOCKED" for g in first["operational_models"].values())
    assert (root / "runtime/network/queue.sqlite").exists()
    assert RuntimeStore(root / "runtime").verify_audit()


def test_read_exact_handles_tcp_segmentation_and_early_eof():
    class Stream:
        def __init__(self, parts):
            self.parts = iter(parts)

        def recv(self, count):
            return next(self.parts)

    assert manual.read_exact(Stream([b"a", b"bc"]), 3) == b"abc"
    with pytest.raises(ValueError, match="INCOMPLETE"):
        manual.read_exact(Stream([b"a", b""]), 3)


@pytest.mark.parametrize("attack", ["none", "uid", "cap", "bounding", "nnp", "fd", "nic"])
def test_ready_checks_os_peer_and_bound_packet_socket(tmp_path, monkeypatch, attack):
    root = tmp_path / "manual"
    session = manual.initialize_session(root)
    receipt = ready(session)
    manual.write_record(root / "ready.json", receipt.model_dump(mode="json"))
    original_text, original_bytes = Path.read_text, Path.read_bytes
    fields = {
        "Uid": "1000 1000 1000 1000",
        "Gid": "1000 1000 1000 1000",
        "CapEff": "0",
        "CapPrm": "0",
        "CapInh": "0",
        "CapAmb": "0",
        "CapBnd": "2000",
        "NoNewPrivs": "1",
        "Groups": "",
    }
    if attack in ("uid", "cap", "bounding", "nnp"):
        key, wrong = {
            "uid": ("Uid", "0 0 0 0"),
            "cap": ("CapEff", "2000"),
            "bounding": ("CapBnd", "ffffffff"),
            "nnp": ("NoNewPrivs", "0"),
        }[attack]
        fields[key] = wrong

    def read_text(path, *args, **kwargs):
        if str(path) == f"/proc/{receipt.pid}/status":
            return "\n".join(k + ": " + v for k, v in fields.items())
        if str(path) == "/proc/net/packet":
            interface = 999 if attack == "nic" else manual.socket.if_nametoindex("lo")
            return f"header\n0 1 3 0003 {interface} 0 0 1000 123\n"
        return original_text(path, *args, **kwargs)

    def read_bytes(path, *args, **kwargs):
        if str(path) == f"/proc/{receipt.pid}/cmdline":
            return b"\0".join(
                [
                    b"python",
                    b"-I",
                    b"-m",
                    manual.MODULE.encode(),
                    b"capture",
                    b"--directory",
                    os.fsencode(root),
                    b"",
                ]
            )
        return original_bytes(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(
        os, "readlink", lambda path: "socket:[999]" if attack == "fd" else "socket:[123]"
    )
    if attack == "none":
        assert manual.validate_ready_peer(root, session) == receipt
    else:
        with pytest.raises(ValueError, match="READY_"):
            manual.validate_ready_peer(root, session)


def test_open_failure_cancels_watchdog_and_never_publishes_ready(tmp_path, monkeypatch):
    root = tmp_path / "manual"
    session = manual.initialize_session(root)
    receiver = manual.ManualCapture(manual.CaptureConfig(interface="lo"), root, session)
    timers = []
    monkeypatch.setattr(manual.signal, "getsignal", lambda value: manual.signal.SIG_DFL)
    monkeypatch.setattr(manual.signal, "setitimer", lambda kind, value: timers.append(value))

    def denied(self):
        raise CaptureUnavailable("FIXTURE_CAPABILITY_DROP_FAILED")

    monkeypatch.setattr(manual.ProbeCapture, "open", denied)
    with pytest.raises(CaptureUnavailable):
        receiver.open()
    assert timers == [4, 0] and receiver.opened is None and receiver.socket is None
    assert not (root / "ready.json").exists()


def test_ready_is_published_only_after_drop_then_closed_before_disarm(tmp_path, monkeypatch):
    root = tmp_path / "manual"
    session = manual.initialize_session(root)
    receiver = manual.ManualCapture(manual.CaptureConfig(interface="lo"), root, session)
    descriptor, writer = os.pipe()  # not a packet socket and no network traffic
    events = []

    class SocketFixture:
        def fileno(self):
            return descriptor

        def close(self):
            events.append("socket_closed")
            os.close(descriptor)

    def dropped_open(self):
        events.append("capability_drop_fixture")
        self.socket = SocketFixture()
        assert not (root / "ready.json").exists()

    p = manual.privileges() | {
        "CapEff": 0,
        "CapPrm": 0,
        "CapInh": 0,
        "CapAmb": 0,
        "CapBnd": 8192,
        "NoNewPrivs": 1,
    }
    monkeypatch.setattr(manual.ProbeCapture, "open", dropped_open)
    monkeypatch.setattr(receiver, "statistics", lambda: (0, 0))
    monkeypatch.setattr(manual, "privileges", lambda: p)
    monkeypatch.setattr(manual.signal, "getsignal", lambda value: manual.signal.SIG_DFL)
    monkeypatch.setattr(
        manual.signal, "setitimer", lambda kind, value: events.append(f"timer_{value}")
    )
    try:
        receiver.open()
        assert manual.read_record(root / "ready.json")["effective"] == 0
        receiver.close()
        assert events == ["timer_4", "capability_drop_fixture", "socket_closed", "timer_0"]
        assert manual.read_record(root / "closed.json")["session_digest"] == session.digest
    finally:
        receiver.close()
        os.close(writer)


@pytest.mark.parametrize("verdict,code", [("VERIFIED", 0), ("PARTIAL", 1), ("BLOCKED", 1)])
def test_verification_exit_code_cannot_mask_incomplete_results(
    tmp_path, monkeypatch, verdict, code
):
    monkeypatch.setattr(manual.sys, "argv", ["manual", "verify", "--directory", str(tmp_path)])
    monkeypatch.setattr(manual, "verify", lambda root: {"status": verdict})
    assert manual.main() == code
