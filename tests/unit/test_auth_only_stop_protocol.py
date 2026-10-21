"""Actual C auth-only serve loop over ordinary-UID Unix sockets, no PAM/Kernel load."""

import os
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.auth_session import AuthenticationQualification
from soc_agent.security_ai.ebpf_tc.contracts import request
from soc_agent.security_ai.ebpf_tc.os_handoff import REPLY

APPROVAL = "61" * 32


@pytest.fixture(scope="module")
def server_binary(tmp_path_factory):
    root = Path(__file__).parents[2] / "src/soc_agent/security_ai/ebpf_tc"
    directory = tmp_path_factory.mktemp("auth-stop-protocol")
    source = directory / "server.c"
    source.write_text(
        '#include "auth_qualification.c"\n'
        "int main(int n,char **v) {if(!getuid() || n!=6)return 3;"
        "struct soc_plan p={0};p.uid=getuid();p.gid=getgid();"
        "p.controller_pid=strtoul(v[2],0,10);p.controller_ticks=strtoull(v[3],0,10);"
        "p.namespace_inode=strtoull(v[4],0,10);p.ifindex=strtoul(v[5],0,10);"
        "memset(p.approval,0x61,32);signal(SIGPIPE,SIG_IGN);"
        "int fd=atoi(v[1]),rc=auth_serve(fd,&p);close(fd);return rc?2:0;}\n"
    )
    executable = directory / "server"
    subprocess.run(
        [
            "cc",
            "-O2",
            "-Wall",
            "-Werror",
            "-Wno-misleading-indentation",
            "-I" + str(root),
            str(source),
            *[str(root / n) for n in ("core.c", "os.c", "trust.c", "handoff.c")],
            "-lcrypto",
            "-o",
            str(executable),
        ],
        capture_output=True,
        check=True,
    )
    return executable


@pytest.fixture
def channel(server_binary):
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    client.settimeout(2)
    ticks = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
    child = subprocess.Popen(
        [
            str(server_binary),
            str(server.fileno()),
            str(os.getpid()),
            ticks,
            str(os.stat("/proc/self/ns/net").st_ino),
            Path("/sys/class/net/lo/ifindex").read_text().strip(),
        ],
        pass_fds=(server.fileno(),),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    server.close()
    try:
        yield client, child
    finally:
        client.close()
        child.wait(timeout=6)


def test_status_then_stop_ack_holds_identity_until_controller_close(channel):
    client, child = channel
    for seq, operation in ((1, "STATUS"), (2, "STOP")):
        client.send(
            request(
                Command(
                    command=operation,
                    plan_digest=APPROVAL,
                    sequence=seq,
                    reason="USER_STOP" if operation == "STOP" else None,
                )
            )
        )
        assert REPLY.unpack(client.recv(4096))[:4] == (seq, 3, 0, 0)
    assert child.poll() is None
    assert Path(f"/proc/{child.pid}/stat").exists()
    client.close()
    assert child.wait(timeout=2) == 0


@pytest.mark.parametrize("kind", ["CLEANUP", "REPLAY", "PARTIAL"])
def test_forbidden_or_malformed_request_fails_closed(channel, kind):
    client, child = channel
    if kind == "REPLAY":
        wire = request(Command(command="STATUS", plan_digest=APPROVAL, sequence=1))
        client.send(wire)
        client.recv(4096)
    else:
        wire = request(Command(command="CLEANUP", plan_digest=APPROVAL, sequence=1))
    client.send(wire[:8] if kind == "PARTIAL" else wire)
    assert client.recv(4096) == b""
    assert child.wait(timeout=2) == 2


def test_stop_rejection_records_close_once():
    auth = object.__new__(AuthenticationQualification)
    auth.state, auth.error, auth.ended = "BROKER_READY", None, False
    auth.plan = SimpleNamespace(approval=APPROVAL)
    auth.sequence, auth.deadline = 1, 1.0
    auth.channel = auth.listener = auth.child = None
    auth.audit_fd = -1
    closed = []
    auth.data = SimpleNamespace(close=lambda: closed.append("data"))
    auth._event = lambda *args, **kwargs: closed.append("audit")
    auth.snapshot = lambda: {"state": auth.state}

    def rejected(_):
        auth.state, auth.error = "ERROR", "HANDOFF_COMMAND_FAILED"
        auth.close()  # Same nested close as command -> _reject -> close.
        raise ValueError("mock rejection")

    auth.command = rejected
    auth.close()
    assert closed == ["data", "audit"]
    assert auth.cleanup == "CLEANUP_UNVERIFIED"
