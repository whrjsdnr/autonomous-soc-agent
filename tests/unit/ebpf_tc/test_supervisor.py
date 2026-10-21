"""Ordinary-user adversarial fixtures: no sudo, capset, BPF syscall or capture."""

import array
import copy
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_tc import supervisor_engine as engine
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorClient


def inventory():
    return {key: {"rows": []} for key in ("programs", "maps", "links", "ingress", "egress")}


class Operations:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail
        self.stopped = False

    def start(self, plan):
        self.calls.append("start")
        if self.fail == "start":
            raise ValueError("FIXTURE_ZEEK_START_FAILED")
        return None

    def stop(self):
        self.calls.append("stop")
        if self.fail == "stop":
            raise ValueError("FIXTURE_CLEANUP_UNVERIFIED")
        self.stopped = True

    def status(self):
        return {"source": "ORDINARY_FIXTURE", "zeek_stopped": self.stopped}

    def inspect(self):
        self.calls.append("inspect")
        return inventory()

    def quiesce(self):
        pass

    def close(self):
        self.calls.append("close")


def request(command, sequence=1, data=None):
    return dict(command=command, sequence=sequence, binding="b" * 64, data=data or {})


def test_single_session_start_status_stop_and_replay():
    ops = Operations()
    core = engine.SupervisorCore(ops, "b" * 64, inventory())
    response, _ = core.dispatch(request("START_ZEEK"))
    assert response["state"] == "ZEEK_READY"
    assert core.dispatch(request("STATUS", 2))[0]["state"] == "ZEEK_READY"
    with pytest.raises(ValueError, match="REQUEST_REJECTED"):
        core.dispatch(request("STATUS", 2))
    response, _ = core.dispatch(request("STOP", 3))
    assert response["state"] == "STOPPING" and ops.stopped
    final = core.finish()
    assert final["cleanup"] == "VERIFIED" and final["native_ai"] == "BLOCKED"
    assert ops.calls[-2:] == ["inspect", "close"]


@pytest.mark.parametrize("fail", ["start", "stop"])
def test_partial_failure_still_inspects_and_closes_both_paths(fail):
    ops = Operations(fail)
    core = engine.SupervisorCore(ops, "b" * 64, inventory())
    response, _ = core.dispatch(request("START_ZEEK" if fail == "start" else "STOP"))
    assert response["error"]
    final = core.finish()
    assert "stop" in ops.calls and ops.calls[-2:] == ["inspect", "close"]
    assert final["first_error"] == response["error"]
    assert final["cleanup"] == ("VERIFIED" if fail == "start" else "CLEANUP_UNVERIFIED")
    assert core.started == (fail == "start")  # Failed start consumes the attempt.


@pytest.mark.parametrize("mutation", ["binding", "sequence", "command", "arguments"])
def test_scope_replay_command_allowlist(mutation):
    value = request("STATUS")
    if mutation == "binding":
        value["binding"] = "c" * 64
    elif mutation == "sequence":
        value["sequence"] = True
    elif mutation == "command":
        value["command"] = ["shell"]
    else:
        value["data"] = {"argv": ["/bin/sh"]}
    with pytest.raises(ValueError, match="REQUEST_REJECTED"):
        engine.sup_validate_request(value, 1, "b" * 64)


def test_inventory_failure_and_foreign_resources_never_admit_attach(monkeypatch):
    calls = []

    def execute(argv, mask):
        calls.append(argv)
        assert mask == engine.SUP_MASK
        if "link" in argv:
            return b'[{"id":1,"type":"tcx"}]'
        return b"[]"

    monkeypatch.setattr(engine, "sup_execute", execute)
    with pytest.raises(ValueError, match="EXISTING_LINK"):
        engine.sup_inventory(dict(bpftool="/fixed/bpftool", tc="/fixed/tc"))
    assert len(calls) == 5

    def denied(*_):
        raise ValueError("QUERY_EPERM")

    monkeypatch.setattr(engine, "sup_execute", denied)
    with pytest.raises(ValueError, match="QUERY_EPERM"):
        engine.sup_inventory(dict(bpftool="/fixed/bpftool", tc="/fixed/tc"))


def test_actual_seqpacket_peer_and_metadata_fd_no_authority(tmp_path):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    try:
        a.send(engine.sup_json(request("STATUS")))
        assert engine.sup_receive(b, (os.getpid(), os.getuid(), os.getgid())) == request("STATUS")
        a.send(engine.sup_json(request("STATUS")))
        with pytest.raises(ValueError, match="PEER_OR_MESSAGE"):
            engine.sup_receive(b, (os.getpid() + 1, os.getuid(), os.getgid()))
        fd = os.open(tmp_path / "ordinary", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            a.sendmsg(
                [engine.sup_json(request("STATUS"))],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))],
            )
            with pytest.raises(ValueError, match="PEER_OR_MESSAGE"):
                engine.sup_receive(b, (os.getpid(), os.getuid(), os.getgid()))
        finally:
            os.close(fd)
    finally:
        a.close()
        b.close()


def test_forged_root_response_rejected_and_received_fd_closed(monkeypatch):
    from soc_agent.security_ai.ebpf_native.contracts import process_identity

    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    client = SupervisorClient(b, process_identity(os.getpid()), "b" * 64)
    before = set(os.listdir("/proc/self/fd"))
    read_fd, write_fd = os.pipe()
    try:
        engine.sup_send(a, {"binding": "b" * 64}, os.dup(read_fd))
        with pytest.raises(ValueError, match="RESPONSE_IDENTITY"):
            client.receive(fd_allowed=True)
    finally:
        os.close(read_fd)
        os.close(write_fd)
        a.close()
        b.close()
    assert set(os.listdir("/proc/self/fd")) <= before


def test_zeek_supervisor_auth_never_calls_sudo(monkeypatch, tmp_path):
    from soc_agent import cli
    from soc_agent.security_ai.collectors.live_contract import new_plan
    from soc_agent.security_ai.collectors.live_process import StreamProcess

    calls = []
    runner = StreamProcess(
        tmp_path,
        new_plan(),
        supervisor=SimpleNamespace(
            authorize=lambda p: calls.append(p.identity), stop_zeek=lambda: True
        ),
    )
    monkeypatch.setattr(runner, "_controller", lambda *args: None)
    monkeypatch.setattr(cli, "terminal_authenticate", lambda: pytest.fail("SECOND_AUTH_FORBIDDEN"))
    runner.authenticate()
    assert calls == [runner.plan.identity] and runner._absent()
    with pytest.raises(ValueError, match="REUSE_DENIED"):
        runner.authenticate()
    with pytest.raises(ValueError, match="ARBITRARY_DOCKER_DENIED"):
        runner._docker("run", "user-controlled-image")


def test_zeek_plan_scope_and_numeric_types():
    from soc_agent.security_ai.collectors.live_contract import new_plan

    p = new_plan().model_dump(mode="json")
    config = {
        "zeek_scope": {
            k: v
            for k, v in p.items()
            if k not in {"session_id", "controller_generation", "net_namespace"}
        }
    }
    assert len(engine.sup_validate_plan(p, config, p["net_namespace"])) == 64
    for key, value in [("interface", "eth0"), ("cpu_limit", True), ("native_inference", "YES")]:
        bad = copy.deepcopy(p)
        bad[key] = value
        with pytest.raises(ValueError, match="ZEEK_SCOPE"):
            engine.sup_validate_plan(bad, config, p["net_namespace"])


def test_no_privileged_execution_during_import_or_prepare_source():
    source = Path(engine.__file__).read_text()
    assert "sudo" not in engine.SUP_COMMANDS
    assert '"ATTACH"' not in engine.SUP_COMMANDS
    assert "supervisor_prepare" in source
    assert "No object, journal, Link or authority FD exists at fork" in source


def test_readonly_metadata_pipe_transfer_is_separate_from_commands():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    read_fd, write_fd = os.pipe()
    body = b"packet-metadata-only" * 4  # Transport fixture, not a Kernel packet.
    try:
        os.write(write_fd, body)
        os.close(write_fd)
        write_fd = -1
        engine.sup_send(a, {"source": "ORDINARY_TRANSPORT_FIXTURE"}, os.dup(read_fd))
        data, ancillary, _, _ = b.recvmsg(16384, socket.CMSG_SPACE(4))
        received = array.array("i")
        received.frombytes(ancillary[0][2])
        assert json.loads(data)["source"] == "ORDINARY_TRANSPORT_FIXTURE"
        try:
            assert os.read(received[0], 4096) == body
            with pytest.raises(OSError):
                os.write(received[0], b"unauthorized control")
        finally:
            os.close(received[0])
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)
        a.close()
        b.close()


def test_cleanup_failure_is_not_retried_and_status_counters_are_not_identity():
    ops = Operations("stop")
    core = engine.SupervisorCore(ops, "b" * 64, inventory())
    core.dispatch(request("STOP"))
    assert core.finish()["cleanup"] == "CLEANUP_UNVERIFIED"
    assert ops.calls.count("stop") == 1 and "inspect" in ops.calls
    fields = ("id", "type", "tag", "map_ids")
    a = {"id": 11, "type": "cgroup_skb", "tag": "aa", "run_cnt": 1}
    b = dict(a, run_cnt=100)
    assert engine.sup_identities([a], fields) == engine.sup_identities([b], fields)
    assert engine.sup_identities([a], fields) != engine.sup_identities([dict(b, tag="bb")], fields)


def test_daemon_stream_demultiplexes_only_bounded_stdout():
    import io
    import struct

    class API:
        def request(self, *_args, **_kwargs):
            body = b'{"kind":"fixture-metadata"}\n'
            return SimpleNamespace(close=lambda: None), io.BytesIO(
                bytes([1, 0, 0, 0]) + struct.pack(">I", len(body)) + body
            )

    r, w = os.pipe()
    stream = engine.DaemonCapture(API(), "a" * 64, w)
    try:
        stream.close()
        assert os.read(r, 4096) == b'{"kind":"fixture-metadata"}\n'
        assert stream.error is None
    finally:
        os.close(r)


def test_container_api_preserves_capability_network_resource_scope():
    from soc_agent.security_ai.collectors.live_contract import docker_argv, new_plan

    p = new_plan()
    config = dict(
        zeek_scope={"image": p.image},
        scripts={name: {} for name in ("live.zeek", "network14.zeek", "visibility.zeek")},
        zeek_argv=docker_argv(p, Path("@POLICY@")),
    )
    value = engine.sup_container(
        p.model_dump(mode="json"), config, "/fixed/root-policy", p.identity
    )
    host = value["HostConfig"]
    assert host["CapDrop"] == ["ALL"] and host["CapAdd"] == ["NET_RAW"]
    assert host["NetworkMode"] == "host" and host["ReadonlyRootfs"]
    assert host["Memory"] == 512 * 1024**2 and host["NanoCpus"] == 1000000000
    assert all(
        m["ReadOnly"] and m["Source"].startswith("/fixed/root-policy/") for m in host["Mounts"]
    )
    assert "-i lo" in value["Cmd"][1] and value["StopSignal"] == "SIGINT"
    assert "Privileged" not in host and not host["AutoRemove"]


def test_foreign_container_identity_never_stopped_or_deleted(monkeypatch):
    class API:
        calls = []

        def __init__(self, *_):
            pass

        def request(self, method, path):
            self.calls.append((method, path))
            return {"Id": "b" * 64, "Config": {"Image": "foreign"}}

    monkeypatch.setattr(engine, "DockerAPI", API)
    ops = engine.RootOperations({}, "net:[4026531833]", "fixture", inspector=None)
    ops.identity = "a" * 64
    with pytest.raises(ValueError, match="OWNERSHIP_UNVERIFIED"):
        ops.stop()
    assert API.calls == [("GET", "/containers/" + "a" * 64 + "/json")]


def test_real_http_attach_boundary_with_ordinary_socketpair(monkeypatch):
    import http.client
    import threading

    a, b = socket.socketpair()
    a.settimeout(5)
    connection = http.client.HTTPConnection("localhost")
    connection.sock = a
    api = engine.DockerAPI()
    monkeypatch.setattr(api, "connect", lambda timeout: connection)

    def serve():
        body = b""
        while b"\r\n\r\n" not in body:
            body += b.recv(4096)
        assert b"/v1.51/containers/fixed/attach" in body
        b.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
        b.sendall(b"metadata-only")
        b.close()

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        _, response = api.request("POST", "/containers/fixed/attach", stream=True)
        assert response.read() == b"metadata-only"
        response.close()
    finally:
        connection.close()
        worker.join(2)
        assert not worker.is_alive()


def test_new_kernel_work_needs_supervisor_but_cleanup_remains_available(monkeypatch):
    from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession
    from soc_agent.security_ai.ebpf_tc.unified import UnifiedSession

    calls = []
    monkeypatch.setattr(UnifiedSession, "command", lambda self, value: calls.append(value.command))
    session = object.__new__(SupervisedSession)
    session.supervisor = None
    with pytest.raises(ValueError, match="SESSION_REQUIRED_FOR_NEW_WORK"):
        session.command(SimpleNamespace(command="ATTACH"))
    session.command(SimpleNamespace(command="CLEANUP"))
    assert calls == ["CLEANUP"]


def test_unclosed_stream_still_uses_isolated_inspector_without_local_fork():
    ops = Operations()

    def fail():
        raise ValueError("STREAM_WORKER_CLOSE_UNVERIFIED")

    ops.quiesce = fail
    core = engine.SupervisorCore(ops, "b" * 64, inventory())
    final = core.finish()
    assert final["cleanup"] == "CLEANUP_UNVERIFIED"
    assert "inspect" in ops.calls and "close" in ops.calls
