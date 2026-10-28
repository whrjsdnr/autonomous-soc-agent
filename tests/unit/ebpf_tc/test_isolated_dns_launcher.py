"""Synthetic syscall/transport fixtures only; no setns, bind, fork or DNS traffic."""

import hashlib
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_root_operations import setup as setup
from tests.unit.ebpf_tc.test_runtime_recovery import package as package
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import isolated_dns_engine as engine
from soc_agent.security_ai.ebpf_tc import isolated_dns_launcher as launcher
from soc_agent.security_ai.ebpf_tc import isolated_dns_worker as worker
from soc_agent.security_ai.ebpf_tc.namespace_isolation import IsolatedScope
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import QUESTION


def lease(binding):
    return dict(
        contract="SOC_NAMESPACE_CREATION_LEASE_V1",
        namespace="net:[4999999999]",
        name="soc-native-b3",
        session=binding.session,
        release=binding.artifact.release,
        deletion_authorized=False,
        owner_uid=0,
        lo_up_command_succeeded=True,
        host_namespace="net:[4026531833]",
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        creation_receipt_sha="a" * 64,
        reservation="a" * 64,
        dev=4,
        inode=4999999999,
    )


@pytest.mark.parametrize(
    "change",
    [
        dict(session="other"),
        dict(release="other"),
        dict(boot_id="stale"),
        dict(namespace="net:[4026531833]"),
        dict(deletion_authorized=True),
        dict(lo_up_command_succeeded=False),
        dict(creation_receipt_sha="not-a-sha"),
        dict(reservation="b" * 64),
    ],
)
def test_lease_binding_rejected_before_namespace_open(setup, monkeypatch, change):
    monkeypatch.setattr(launcher, "held_json", lambda *_: lease(setup.binding) | change)
    monkeypatch.setattr(launcher.os, "open", lambda *_: pytest.fail("No namespace open"))
    with pytest.raises(ValueError):
        launcher.inspect_lease(Path("fixture"), "c" * 64, setup.binding)


def test_replaced_namespace_fd_closed(setup, monkeypatch):
    monkeypatch.setattr(launcher, "held_json", lambda *_: lease(setup.binding))
    monkeypatch.setattr(launcher.os, "open", lambda *_: 123)
    monkeypatch.setattr(
        launcher.os, "fstat", lambda *_: SimpleNamespace(st_dev=4, st_ino=999, st_uid=0)
    )
    closed = []
    monkeypatch.setattr(launcher.os, "close", closed.append)
    with pytest.raises(ValueError, match="NAMESPACE_REPLACED"):
        launcher.inspect_lease(Path("fixture"), "c" * 64, setup.binding)
    assert closed == [123]


def test_deterministic_review_image_and_no_execution(tmp_path, setup, monkeypatch):
    monkeypatch.setattr(launcher, "inspect_lease", lambda *_: lease(setup.binding))
    outputs = [tmp_path / "A.py", tmp_path / "B.py"]
    results = [
        launcher.prepare_dns_launcher(Path("fixture"), "c" * 64, setup.binding, p) for p in outputs
    ]
    assert outputs[0].read_bytes() == outputs[1].read_bytes()
    assert results[0] == results[1]
    assert results[0]["image_sha256"] == hashlib.sha256(outputs[0].read_bytes()).hexdigest()
    assert results[0]["state"] == "BUILT_NOT_AUTHORIZED"
    assert not results[0]["traffic_executed"]
    scope = results[0]["scope"]
    assert scope["setup_binding"] == setup.binding.model_dump()
    assert (scope["udp_queries"], scope["tcp_queries"], scope["sidecar_analysis_seconds"]) == (
        2,
        1,
        10,
    )
    namespace = {"__name__": "review_fixture"}
    exec(compile(outputs[0].read_bytes(), "fixture", "exec"), namespace)
    assert callable(namespace["spawn_dns_child"])
    assert callable(namespace["serve_prebound"])
    with pytest.raises(SystemExit, match="LIFECYCLE_APPROVAL_REQUIRED"):
        exec(compile(outputs[0].read_bytes(), "fixture", "exec"), {"__name__": "__main__"})
    with pytest.raises(FileExistsError):
        launcher.prepare_dns_launcher(Path("fixture"), "c" * 64, setup.binding, outputs[0])


def test_ordinary_caller_cannot_launch(monkeypatch):
    monkeypatch.setattr(engine.os, "fork", lambda: pytest.fail("No fork"))
    with pytest.raises(ValueError, match="AUTHENTICATED_ROOT_SUPERVISOR"):
        engine.spawn_dns_child({}, lambda *_: None)
    with pytest.raises(ValueError, match="AUTHENTICATED_ROOT_SUPERVISOR"):
        engine.dns_child({}, lambda *_: None, lambda *_: None)


@pytest.mark.parametrize("failure", ["drop", "worker", None])
def test_child_cleanup_and_privilege_order(monkeypatch, failure):
    events = []

    class Channel:
        def close(self):
            events.append("close")

    monkeypatch.setattr(engine.os, "getuid", lambda: 0)
    monkeypatch.setattr(engine.os, "geteuid", lambda: 0)
    monkeypatch.setattr(engine, "_prctl", lambda *_: None)
    monkeypatch.setattr(engine.signal, "signal", lambda *_: None)
    monkeypatch.setattr(engine.resource, "setrlimit", lambda *a: events.append("limit"))
    monkeypatch.setattr(engine.signal, "alarm", lambda value: events.append(("alarm", value)))
    monkeypatch.setattr(engine, "_enter_and_bind", lambda _: (Channel(), Channel()))

    def drop(*_):
        events.append("drop")
        if failure == "drop":
            raise ValueError("drop")

    def worker(*_, **__):
        assert "drop" in events
        events.append("worker")
        if failure == "worker":
            raise ValueError("worker")
        return {"queries": 3}

    monkeypatch.setattr(engine, "_drop_credentials", drop)
    if failure:
        with pytest.raises(ValueError, match=failure):
            engine.dns_child(
                dict(uid=1000, gid=1000, namespace="net:[4999999999]"), lambda *_: None, worker
            )
    else:
        assert engine.dns_child(
            dict(uid=1000, gid=1000, namespace="net:[4999999999]"), lambda *_: None, worker
        ) == {"queries": 3}
    assert events[-3:] == ["close", "close", ("alarm", 0)]
    assert ("worker" in events) == (failure != "drop")


def test_credential_drop_cannot_retain_root(monkeypatch):
    monkeypatch.setattr(engine, "_prctl", lambda *_: pytest.fail("No privilege change"))
    for uid, gid in ((0, 1000), (1000, 0), (-1, 1000)):
        with pytest.raises(ValueError, match="ROOT_IDENTITY_FORBIDDEN"):
            engine._drop_credentials(uid, gid, 123)


@pytest.mark.parametrize("running", [True, False])
def test_supervisor_closes_only_its_owned_unreaped_child(monkeypatch, running):
    calls = []
    status = iter([(0, 0), (123, 9)] if running else [(123, 0)])
    monkeypatch.setattr(engine.os, "waitpid", lambda *a: next(status))
    monkeypatch.setattr(engine.os, "kill", lambda *a: calls.append(a))
    channel = SimpleNamespace(close=lambda: calls.append("close"))
    child = engine.DNSChild(123, channel)
    assert child.close() == (-9 if running else 0)
    assert child.close() == (-9 if running else 0)
    assert calls.count((123, engine.signal.SIGKILL)) == int(running)


def test_evidence_truncation_stops_owned_child(monkeypatch):
    channel = SimpleNamespace(recvmsg=lambda *_: (b"{}", [], engine.socket.MSG_TRUNC, None))
    child = engine.DNSChild(123, channel)
    stopped = []
    monkeypatch.setattr(child, "close", lambda: stopped.append(True))
    monkeypatch.setattr(engine.select, "select", lambda *_: ([channel], [], []))
    with pytest.raises(ValueError, match="EVIDENCE_TRUNCATED"):
        child.receive()
    assert stopped == [True]


@pytest.mark.parametrize("body", [b"{", b"\xff", b"[]", b'{"state":"UNREVIEWED"}'])
def test_invalid_evidence_closes_owned_child_and_preserves_error(monkeypatch, body):
    channel = SimpleNamespace(recvmsg=lambda *_: (body, [], 0, None))
    child = engine.DNSChild(123, channel)
    stopped = []
    monkeypatch.setattr(child, "close", lambda: stopped.append(True))
    monkeypatch.setattr(engine.select, "select", lambda *_: ([channel], [], []))
    with pytest.raises((ValueError, UnicodeError)):
        child.receive()
    assert stopped == [True]


def test_evidence_transport_error_closes_child_without_masking_first_error(monkeypatch):
    failure = OSError("FIXTURE_TRANSPORT_FAILURE")

    def receive(*_):
        raise failure

    channel = SimpleNamespace(recvmsg=receive)
    child = engine.DNSChild(123, channel)
    stopped = []
    monkeypatch.setattr(child, "close", lambda: stopped.append(True))
    monkeypatch.setattr(engine.select, "select", lambda *_: ([channel], [], []))
    with pytest.raises(OSError) as caught:
        child.receive()
    assert caught.value is failure and stopped == [True]


def test_normal_completion_reaps_without_cancellation_signal(monkeypatch):
    statuses = iter([(0, 0), (123, 0)])
    monkeypatch.setattr(engine.os, "waitpid", lambda *_: next(statuses))
    monkeypatch.setattr(engine.os, "kill", lambda *_: pytest.fail("Normal exit must not be killed"))
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    closed = []
    child = engine.DNSChild(123, SimpleNamespace(close=lambda: closed.append(True)))
    assert child.finish() == 0
    assert closed == [True]


def test_no_new_public_execution_entry():
    # Image is for review; no separate approval issuer or shell command runner.
    assert not hasattr(launcher, "execute")
    assert not hasattr(launcher, "issue_receipt")
    assert "subprocess" not in engine.__dict__


@pytest.mark.parametrize("late_seconds", [34, 35])
def test_prebound_worker_protocol_window_and_cleanup(monkeypatch, late_seconds):
    """Actual transport worker + protocol engine, fake sockets and monotonic clock."""
    clock = [0]
    events = []

    def query(transaction):
        return struct.pack("!6H", transaction, 0x100, 1, 0, 0, 0) + QUESTION

    class Channel:
        def __init__(self, kind):
            self.kind = kind
            self.closed = False
            self.queries = iter([query(0xC201), query(0xC203)])
            body = query(0xC202)
            self.stream = bytearray(struct.pack("!H", len(body)) + body)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.closed = True

        def getsockname(self):
            return ("127.0.0.53", 53)

        def getsockopt(self, _level, option, *args):
            return self.kind if option == worker.socket.SO_TYPE else b"cookie00"

        def recvfrom(self, *_):
            return next(self.queries), ("127.0.0.1", 12345)

        def sendto(self, body, *_):
            return len(body)

        def accept(self):
            return stream, ("127.0.0.1", 12345)

        def getpeername(self):
            return ("127.0.0.1", 12345)

        def recv(self, size):
            body = bytes(self.stream[:size])
            del self.stream[:size]
            return body

        def settimeout(self, _):
            pass

        def sendall(self, body):
            events.append(body)

        def shutdown(self, _):
            pass

    udp, tcp, stream, probe = [Channel(k) for k in (2, 1, 1, 2)]
    schedule = iter([(1, udp), (2, tcp), (2 + late_seconds, udp)])

    def select(*_):
        second, channel = next(schedule)
        clock[0] = second * 1_000_000_000
        return [channel], [], []

    monkeypatch.setattr(worker, "local_controller", lambda: None)
    monkeypatch.setattr(worker.os, "readlink", lambda _: "net:[4999999999]")
    monkeypatch.setattr(worker.socket, "socket", lambda *_: probe)
    monkeypatch.setattr(worker.select, "select", select)
    monkeypatch.setattr(worker.time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(worker.time, "monotonic", lambda: clock[0] / 1_000_000_000)
    if late_seconds < 35:
        with pytest.raises(ValueError, match="LATE_WITNESS_TOO_EARLY"):
            worker.serve_prebound(
                IsolatedScope(namespace="net:[4999999999]"), udp, tcp, ready=events.append
            )
    else:
        result = worker.serve_prebound(
            IsolatedScope(namespace="net:[4999999999]"), udp, tcp, ready=events.append
        )
        assert result["queries"] == 3
        assert result["capture_integrity"] == "NOT_ASSESSED"
        assert result["tcp_closed_application_ns"] == 2_000_000_000
        assert result["events"][-1]["application_monotonic_ns"] == 37_000_000_000
    assert udp.closed and tcp.closed and stream.closed and probe.closed


@pytest.mark.parametrize("failure", [None, "mount", "namespace", "lo", "route", "cookie", "bind"])
def test_fixed_namespace_entry_and_bind_failure_cleanup(monkeypatch, failure):
    import fcntl

    channels = []
    calls = []
    reuse = []

    class Channel:
        closed = False

        def __init__(self, *args):
            self.index = len(channels)
            channels.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.close()

        def close(self):
            self.closed = True

        def getsockopt(self, *_):
            return b"different" if failure == "cookie" and self.index else b"cookie00"

        def setsockopt(self, level, option, value):
            assert self.index == 2  # Only the newly created TCP listener.
            assert (level, option, value) == (
                engine.socket.SOL_SOCKET,
                engine.socket.SO_REUSEADDR,
                1,
            )
            reuse.append(value)

        def bind(self, endpoint):
            assert endpoint == ("127.0.0.53", 53)
            if failure == "bind":
                raise PermissionError("fixture permission denied")

        def set_inheritable(self, value):
            assert value is False

        def listen(self, size):
            assert size == 1

    monkeypatch.setattr(engine.os, "open", lambda *_: 123)
    monkeypatch.setattr(engine.os, "close", lambda fd: calls.append(("close", fd)))
    monkeypatch.setattr(
        engine.os,
        "fstat",
        lambda _: SimpleNamespace(st_dev=4, st_ino=123 if failure == "mount" else 999, st_uid=0),
    )
    monkeypatch.setattr(engine.os, "setns", lambda *args: calls.append(("setns", args)))
    monkeypatch.setattr(
        engine.os,
        "readlink",
        lambda _: "net:[4026531833]" if failure == "namespace" else "net:[999]",
    )
    monkeypatch.setattr(engine.socket, "socket", Channel)
    monkeypatch.setattr(engine.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(
        fcntl, "ioctl", lambda *_: bytes(16) + struct.pack("H", 0 if failure == "lo" else 1)
    )

    def text(path):
        return {
            "/proc/sys/kernel/random/boot_id": "fixtureboot",
            "/proc/net/route": "header\neth0 0 0" if failure == "route" else "header\n",
            "/proc/net/ipv6_route": "",
        }[str(path)]

    monkeypatch.setattr(engine.Path, "read_text", text)
    config = dict(
        namespace_device=4, namespace_inode=999, namespace="net:[999]", boot_id="fixtureboot"
    )
    if failure:
        with pytest.raises((ValueError, PermissionError)):
            engine._enter_and_bind(config)
        assert all(channel.closed for channel in channels)
    else:
        udp, tcp = engine._enter_and_bind(config)
        assert channels[0].closed and not udp.closed and not tcp.closed
        udp.close()
        tcp.close()
    assert reuse == ([] if failure else [1])
    assert calls[-1] == ("close", 123)
    assert any(call[0] == "setns" for call in calls) == (failure != "mount")


def test_drop_all_privileges_before_worker_and_check_parent_race(monkeypatch):
    events = []
    monkeypatch.setattr(engine.Path, "read_text", lambda _: "2")
    monkeypatch.setattr(engine, "_prctl", lambda *args: events.append(args))
    monkeypatch.setattr(engine.os, "setgroups", lambda args: events.append(("groups", args)))
    monkeypatch.setattr(engine.os, "setresgid", lambda *args: events.append(("gid", args)))
    monkeypatch.setattr(engine.os, "setresuid", lambda *args: events.append(("uid", args)))
    monkeypatch.setattr(engine.os, "getppid", lambda: 123)
    monkeypatch.setattr(engine, "local_controller", lambda: events.append("verified"))
    engine._drop_credentials(1000, 1000, 123)
    assert events == [
        (47, 4),
        (24, 0),
        (24, 1),
        (24, 2),
        ("groups", []),
        ("gid", (1000, 1000, 1000)),
        ("uid", (1000, 1000, 1000)),
        (38, 1),
        (1, engine.signal.SIGKILL),
        "verified",
    ]
    with pytest.raises(ValueError, match="SUPERVISOR_DISAPPEARED"):
        engine._drop_credentials(1000, 1000, 456)
