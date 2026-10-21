"""No Root execution, capset, BPF query, sudo or capture. Real IPC is ordinary UID."""

import os
import socket
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_tc import inspector_engine as inspector
from soc_agent.security_ai.ebpf_tc import supervisor_engine as supervisor
from soc_agent.security_ai.ebpf_tc.installation import InspectorProfile
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession
from soc_agent.security_ai.ebpf_tc.unified import UnifiedSession


def empty_inventory():
    return {name: {"rows": []} for name in ("programs", "maps", "links", "ingress", "egress")}


def request(command, sequence=1, binding="b" * 64):
    return dict(binding=binding, sequence=sequence, command=command)


def test_readonly_role_capabilities_and_fixed_inventory_commands(monkeypatch):
    assert InspectorProfile().model_dump(mode="json") == inspector.INSPECT_PROFILE
    calls = []
    monkeypatch.setattr(
        supervisor, "sup_execute", lambda argv, mask: calls.append((argv, mask)) or b"[]"
    )
    config = dict(bpftool="/fixed/bpftool", tc="/fixed/tc")
    assert supervisor.sup_inventory(config, mask=inspector.INSPECT_MASK) == {
        key: {"rows": [], "sha256": supervisor.hashlib.sha256(b"[]").hexdigest()}
        for key in empty_inventory()
    }
    assert [argv[1:] for argv, _ in calls] == [
        ["-j", "prog", "show"],
        ["-j", "map", "show"],
        ["-j", "link", "show"],
        ["-j", "filter", "show", "dev", "lo", "ingress"],
        ["-j", "filter", "show", "dev", "lo", "egress"],
    ]
    assert [mask for _, mask in calls] == [1 << 21, 1 << 21, 1 << 21, 0, 0]
    assert supervisor.SUP_MASK == (1 << 39) | (1 << 12)
    assert not supervisor.SUP_MASK & (1 << 21)
    assert inspector.inspector_expected_caps() == dict(
        CapEff=0,
        CapPrm=1 << 21,
        CapInh=0,
        CapAmb=0,
        CapBnd=1 << 21,
    )


def test_start_and_final_inspection_share_worker_then_revoke():
    calls = []
    core = inspector.InspectorCore(
        "b" * 64,
        "net:[1]",
        lambda: calls.append("query") or empty_inventory(),
        lambda: ("net:[1]", 1),
    )
    assert core.dispatch(request("SNAPSHOT"))["phase"] == "BEFORE"
    assert core.dispatch(request("SNAPSHOT", 2))["phase"] == "AFTER"
    assert core.dispatch(request("STOP", 3))["state"] == "CLOSED"
    with pytest.raises(ValueError, match="REQUEST_REJECTED"):
        core.dispatch(request("SNAPSHOT", 4))
    assert calls == ["query", "query"]


@pytest.mark.parametrize("mutation", ["command", "arguments", "binding", "replay", "namespace"])
def test_no_arbitrary_commands_replay_or_changed_scope(mutation):
    calls = []
    core = inspector.InspectorCore(
        "b" * 64,
        "net:[1]",
        lambda: calls.append("query"),
        lambda: ("net:[2]" if mutation == "namespace" else "net:[1]", 1),
    )
    value = request("SNAPSHOT")
    if mutation == "command":
        value["command"] = "ATTACH"
    elif mutation == "arguments":
        value["path"] = "/bin/sh"
    elif mutation == "binding":
        value["binding"] = "c" * 64
    elif mutation == "replay":
        value["sequence"] = 0
    with pytest.raises(ValueError):
        core.dispatch(value)
    assert not calls


def test_query_failure_is_not_absence_and_cannot_retry_but_stop_works():
    calls = []

    def denied():
        calls.append("query")
        raise PermissionError(1, "fixture")

    core = inspector.InspectorCore("b" * 64, "net:[1]", denied, lambda: ("net:[1]", 1))
    with pytest.raises(PermissionError) as error:
        core.dispatch(request("SNAPSHOT"))
    assert error.value.errno == 1
    with pytest.raises(ValueError, match="NO_RETRY"):
        core.dispatch(request("SNAPSHOT", 2))
    assert core.dispatch(request("STOP", 3))["state"] == "CLOSED"
    assert calls == ["query"]


def test_foreign_link_is_not_adopted_or_deleted(monkeypatch):
    calls = []

    def tool(argv, mask):
        calls.append(argv)
        return b'[{"id":9,"type":"tcx"}]' if "link" in argv else b"[]"

    monkeypatch.setattr(supervisor, "sup_execute", tool)
    with pytest.raises(ValueError, match="EXISTING_LINK"):
        supervisor.sup_inventory(
            dict(bpftool="/fixed/bpftool", tc="/fixed/tc"), mask=inspector.INSPECT_MASK
        )
    assert len(calls) == 5 and all("show" in argv for argv in calls)


def test_real_ipc_credentials_reject_forged_root_peer():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    try:
        supervisor.sup_send(a, request("SNAPSHOT"))
        assert supervisor.sup_receive(b, (os.getpid(), os.getuid(), os.getgid())) == request(
            "SNAPSHOT"
        )
        supervisor.sup_send(a, request("SNAPSHOT"))
        with pytest.raises(ValueError, match="PEER_OR_MESSAGE"):
            supervisor.sup_receive(b, (os.getpid(), 0, 0))
    finally:
        a.close()
        b.close()


def test_ordinary_runtime_cannot_start_privileged_inspector(monkeypatch):
    def forbidden():
        pytest.fail("No fork or privilege change before Root boundary")

    monkeypatch.setattr(os, "fork", forbidden)
    with pytest.raises(ValueError, match="AUTHENTICATED_ROOT_REQUIRED"):
        inspector.start_inspector(
            {
                "inspector": inspector.INSPECT_PROFILE,
                "bpftool_version": {"version": "7.4.0", "features": {"skeletons": False}},
            },
            "b" * 64,
            "net:[1]",
            (os.getpid(), 1, os.getuid()),
        )


def test_post_inspection_failure_does_not_skip_inspector_disposal():
    calls = []

    class Worker:
        exit_evidence = None

        def snapshot(self):
            calls.append("post_inspection")
            raise PermissionError(1, "fixture")

        def close(self):
            calls.append("inspector_close")
            self.exit_evidence = dict(cleanup="VERIFIED")

    ops = object.__new__(supervisor.RootOperations)
    ops.inspector = Worker()
    ops.policy = None
    ops.capture = None
    ops.stop = lambda: calls.append("stop_collector")
    final = supervisor.SupervisorCore(ops, "b" * 64, empty_inventory()).finish()
    assert calls == ["stop_collector", "post_inspection", "inspector_close"]
    assert final["after"] is None and final["cleanup"] == "CLEANUP_UNVERIFIED"
    assert final["inspector_exit"]["cleanup"] == "VERIFIED"


def test_supervisor_failure_still_calls_owned_tcx_cleanup(monkeypatch):
    calls = []
    session = object.__new__(SupervisedSession)
    session.entry_diagnostic_listener = None
    session.ended = False
    session.error = None
    session.supervisor_listener = None
    session._event = lambda *a, **kw: None
    session.supervisor = SimpleNamespace(
        request=lambda _: (_ for _ in ()).throw(OSError("fixture Inspector failure")),
        final={"final": {"cleanup": "CLEANUP_UNVERIFIED"}},
        channel=SimpleNamespace(close=lambda: calls.append("supervisor_channel_close")),
    )
    monkeypatch.setattr(UnifiedSession, "close", lambda self: calls.append("OWNED_TCX_FD_CLEANUP"))
    monkeypatch.setattr(SupervisedSession, "snapshot", lambda self: {"cleanup": self.cleanup})
    result = session.close()
    assert calls == ["OWNED_TCX_FD_CLEANUP", "supervisor_channel_close"]
    assert result["cleanup"] == "CLEANUP_UNVERIFIED"


def test_inspector_pid_reuse_blocks_request_before_send(monkeypatch):
    calls = []
    client = inspector.InspectorClient(None, 100, 10, "b" * 64, {}, 0)
    monkeypatch.setattr(inspector, "sup_alive", lambda *_: False, raising=False)
    monkeypatch.setattr(inspector, "sup_send", lambda *_: calls.append("send"), raising=False)
    with pytest.raises(ValueError, match="PROCESS_CHANGED"):
        client.request("SNAPSHOT")
    assert calls == []


@pytest.mark.parametrize("exited", [True, False])
def test_inspector_disposal_closes_actual_socket_and_requires_exit_receipt(monkeypatch, exited):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = inspector.InspectorClient(a, 100, 10, "b" * 64, {}, 0)
    monkeypatch.setattr(client, "request", lambda _: {"state": "CLOSED"})
    monkeypatch.setattr(os, "waitpid", lambda *_: (100, 0))
    clock = iter([0, 1, 4]) if exited else iter([0, 4])
    monkeypatch.setattr(inspector.time, "monotonic", lambda: next(clock))
    try:
        if exited:
            assert client.close()["cleanup"] == "VERIFIED"
        else:
            with pytest.raises(ValueError, match="EXIT_UNVERIFIED"):
                client.close()
            assert client.exit_evidence["authority_revoked"] is False
        assert a.fileno() == -1 and client.closed
    finally:
        b.close()


@pytest.mark.parametrize("mode", [0o4755, 0o777])
def test_inspection_tools_cannot_reintroduce_privilege_or_mutable_execution(monkeypatch, mode):
    monkeypatch.setattr(
        supervisor, "SUPERVISOR_CONFIG", {"tools": {"/fixed/tool": {"mode": mode}}}, raising=False
    )
    with pytest.raises(ValueError, match="PRIVILEGED_OR_MUTABLE_MODE"):
        supervisor.sup_executable("/fixed/tool")


def test_inspector_helper_sets_parent_death_before_capabilities_without_native_calls(
    monkeypatch, tmp_path
):
    calls = []
    executable = tmp_path / "not-executed"
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(supervisor, "sup_executable", lambda _: os.open(executable, os.O_RDONLY))
    monkeypatch.setattr(
        supervisor, "sup_parent_death", lambda parent: calls.append(("parent", parent))
    )
    monkeypatch.setattr(supervisor, "sup_caps", lambda mask, **kw: calls.append(("caps", mask)))
    monkeypatch.setattr(supervisor, "SUPERVISOR_REDUCED", True, raising=False)
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda *a, **kw: kw["preexec_fn"]())
    supervisor.sup_tool(["/fixed/tool", "-j", "prog", "show"], inspector.INSPECT_MASK)
    assert calls == [("parent", os.getpid()), ("caps", inspector.INSPECT_MASK)]


def test_post_inspection_keeps_residual_link_evidence_and_never_claims_cleanup():
    calls = []
    before = empty_inventory()
    after = empty_inventory()
    after["links"]["rows"] = [{"id": 7, "type": "tcx", "prog_id": 9}]
    with pytest.raises(ValueError, match="EXISTING_LINK"):
        supervisor.sup_require_clear(after)
    worker = SimpleNamespace(snapshot=lambda: after, close=lambda: calls.append("inspector_close"))
    ops = object.__new__(supervisor.RootOperations)
    ops.inspector, ops.policy, ops.capture = worker, None, None
    ops.stop = lambda: calls.append("stop_collector")
    final = supervisor.SupervisorCore(ops, "b" * 64, before).finish()
    assert final["after"]["links"]["rows"][0]["id"] == 7
    assert "SUPERVISOR_RESOURCE_SET_CHANGED:links" in final["failures"]
    assert final["cleanup"] == "CLEANUP_UNVERIFIED"
    assert calls == ["stop_collector", "inspector_close"]


@pytest.mark.parametrize("skeletons", [True, None])
def test_inspector_rejects_autoload_or_unknown_tool_build_before_root_work(skeletons):
    config = {
        "inspector": inspector.INSPECT_PROFILE,
        "bpftool_version": {"version": "7.4.0", "features": {"skeletons": skeletons}},
    }
    with pytest.raises(ValueError, match="AUTOLOAD_BUILD_FORBIDDEN"):
        inspector.start_inspector(config, "b" * 64, "net:[1]", (1, 1, 1))
