"""Ordinary-user IPC/PTY only. No sudo, authentication, packet socket or traffic."""

import json
import os
import socket
import subprocess
import time

import pytest

from soc_agent.security_ai.collectors.start_channel import (
    root_error,
    start_binding,
    start_connect,
    start_listener,
    start_peer,
    start_receive,
    start_send,
)


def binding():
    return start_binding(
        bytes(64) + os.urandom(16) + bytes(272), "a" * 64, "b" * 64, "c" * 64, "d" * 64
    )


def test_tty_stdin_is_inherited_while_protocol_stdout_is_separate():
    master, slave = os.openpty()
    try:
        program = (
            "import subprocess,sys;"
            'p=subprocess.run([sys.executable,"-c","import os;print(os.isatty(0))"],'
            "stdin=None,stdout=subprocess.PIPE,text=True,check=True);print(p.stdout.strip())"
        )
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-c", program],
            stdin=slave,
            capture_output=True,
            text=True,
            timeout=3,
        )
        assert result.returncode == 0 and result.stdout.strip() == "True"
    finally:
        os.close(master)
        os.close(slave)


def test_real_session_channel_peer_binding_and_cleanup():
    value = binding()
    with start_listener(os.getuid(), value) as listener:
        with start_connect(
            os.getuid(), os.getgid(), os.getpid(), value, time.monotonic() + 1
        ) as client:
            with listener.accept()[0] as server:
                start_peer(server, os.getuid(), os.getgid(), os.getpid())
                with pytest.raises(ValueError, match="PEER_MISMATCH"):
                    start_peer(server, os.getuid(), os.getgid(), os.getpid() + 1)
                start_send(server, value, time.monotonic() + 1)
                start_receive(client, value, time.monotonic() + 1)
    # Abstract address is released, with no filesystem path to remove.
    with start_listener(os.getuid(), value):
        pass


@pytest.mark.parametrize(
    "field", ["session", "image", "manifest", "approval", "scope", "type", "sequence"]
)
def test_mismatch_and_replay_sequence_fail_closed(field):
    expected = binding()
    changed = expected | {field: 2 if field == "sequence" else "0"}
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with a, b:
        start_send(a, changed, time.monotonic() + 1)
        with pytest.raises(ValueError, match="BINDING_MISMATCH"):
            start_receive(b, expected, time.monotonic() + 1)


def test_timeout_length_and_second_command_are_not_success():
    value = binding()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with a, b:
        with pytest.raises(TimeoutError):
            start_receive(b, value, time.monotonic() + 0.01)
        a.send(b"x" * 1025)
        with pytest.raises(ValueError, match="LENGTH"):
            start_receive(b, value, time.monotonic() + 1)
        start_send(a, value, time.monotonic() + 1)
        start_send(a, value, time.monotonic() + 1)
        with pytest.raises(ValueError, match="REPLAY"):
            start_receive(b, value, time.monotonic() + 1)


def test_error_redaction_preserves_errno_without_exception_secrets():
    value = root_error(PermissionError(13, "password=secret-token"), "PASSWORD_POLICY", "policy")
    assert value["errno"] == 13 and value["exit_code"] == 1
    assert "secret" not in json.dumps(value)
    value = root_error(ValueError("UNIFIED_PASSWORD_POLICY_REJECTED"), "PASSWORD_POLICY", "policy")
    assert value["original_code"] == "UNIFIED_PASSWORD_POLICY_REJECTED"
