"""Actual ordinary-UID C/Python seqpacket handoff; never sudo/authentication/kernel."""

import array
import hashlib
import os
import socket
import struct
import time
from uuid import uuid4

import pytest

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_tc.journal import recover_native
from soc_agent.security_ai.ebpf_tc.os_handoff import AuthenticationFixture, Handoff


def authenticate(handoff):
    handoff.approve(handoff.approval)
    return handoff.authenticate_fixture(AuthenticationFixture())


def test_real_cross_process_handoff_session_commands_audit_recovery(session):
    h, prep = session
    value = authenticate(h)
    assert value["state"] == "BROKER_READY"
    assert value["os_authentication"] == "MOCK_VERIFIED_NOT_NATIVE"
    assert value["native_gate"] == "BLOCKED" and not h.application._authenticated
    first = h.identity
    for number in range(1, 4):
        assert (
            h.command(Command(command="STATUS", plan_digest=h.plan.approval, sequence=number))[
                "state"
            ]
            == 3
        )
    h.stop()
    h.command(Command(command="PREPARE", plan_digest=h.plan.approval, sequence=h.sequence + 1))
    assert h.identity == first  # same app-session authority after stop/prepare, no new auth
    assert prep.snapshot()["os_auth_handoff"]["broker_session"] == value["broker_session"]
    final = h.close()
    assert final["cleanup_status"] == "FIXTURE_VERIFIED"
    assert final["os_authentication"] == "REVOKED" and h.child.poll() == 0
    journal = recover_native(h.audit_path, h.plan.approval)
    assert journal["claimed_cleanup"] and not journal["authentication_restored"]
    assert not journal["automatic_attach"] and not journal["automatic_inference"]
    assert h.application.store.verify_audit()
    with pytest.raises(ValueError, match="REPLAY"):
        replacement = Handoff(h.application, h.plan, h.package, h.release.identity, h.artifacts)
        replacement.prepare()


@pytest.mark.parametrize(
    "facts",
    [
        {"cache_bypassed": False},
        {"nopasswd": True},
        {"password_required": False},
        {"tty": False},
        {"account_allowed": False},
        {"outcome": "FAILURE"},
        {"outcome": "CANCELLED"},
        {"outcome": "TIMEOUT"},
    ],
)
def test_os_policy_denial_never_spawns_or_creates_authority(session, facts):
    h, _ = session
    h.approve(h.approval)
    with pytest.raises(ValueError, match="PASSWORD_CONTRACT"):
        h.authenticate_fixture(AuthenticationFixture(**facts))
    assert h.child is None and h.identity is None and h.ended
    assert h.snapshot()["os_authentication"] == "REVOKED"
    with pytest.raises(ValueError, match="REPLAY"):
        h.authenticate_fixture(AuthenticationFixture())


def test_explicit_approval_and_no_native_runner(session):
    h, _ = session
    with pytest.raises(ValueError, match="APPROVAL"):
        h.approve("0" * 64)
    with pytest.raises(ValueError, match="QUALIFICATION_PENDING"):
        h.authenticate_native()
    assert h.child is None
    argv = h.sudo_command()
    assert argv[:6] == (
        "/usr/bin/sudo",
        "-k",
        "-u",
        "root",
        "--",
        "/usr/libexec/soc-agent-ebpf/bootstrap",
    )
    assert not any(v in argv for v in ("-S", "-A", "-K", "-E", "sh", "-C"))
    assert argv[6:] == (
        "--os-handoff",
        str(os.getuid()),
        str(os.getgid()),
        h.plan.broker.application.application_session.hex,
        h.approval,
        h.release.identity,
    )


@pytest.mark.parametrize("mutation", ["sequence", "digest", "expiration", "broker_crash", "ticks"])
def test_command_session_failure_revokes_authority(session, mutation):
    h, _ = session
    authenticate(h)
    sequence, approval = 1, h.plan.approval
    if mutation == "sequence":
        sequence = 2
    elif mutation == "digest":
        approval = "0" * 64
    elif mutation == "expiration":
        h.deadline = time.monotonic() - 1
    elif mutation == "ticks":
        h.identity = h.identity.model_copy(update={"start_ticks": h.identity.start_ticks + 1})
    else:
        h.child.kill()  # own ordinary-UID transport fixture only
        h.child.wait(timeout=3)
    with pytest.raises((ValueError, OSError, EOFError)):
        h.command(Command(command="STATUS", plan_digest=approval, sequence=sequence))
    assert h.ended and h.authentication == "REVOKED" and h.state == "ERROR"
    assert h.snapshot()["native_gate"] == "BLOCKED"


@pytest.mark.parametrize(
    "field",
    [
        "uid",
        "gid",
        "controller_pid",
        "namespace_inode",
        "ifindex",
        "hook",
        "duration",
        "events",
        "rss_mib",
    ],
)
def test_c_rejects_mutated_scope_or_identity_before_ready(session, field):
    h, _ = session
    # Re-sign outer envelope: checksum agreement alone must not grant authority.
    import ctypes

    library = ctypes.CDLL(str(h.artifacts / "libnative-tc.so"))
    from soc_agent.security_ai.ebpf_tc.contracts import PLAN

    offsets = {
        "uid": 1,
        "gid": 2,
        "controller_pid": 3,
        "namespace_inode": 5,
        "ifindex": 6,
        "hook": 7,
        "duration": 8,
        "events": 9,
        "rss_mib": 11,
    }
    values = list(PLAN.unpack(h.envelope[:272]))
    values[offsets[field]] += 1
    wire = PLAN.pack(*values)
    wire = wire[:-32] + hashlib.sha256(wire[:-32] + bytes(32)).digest()
    envelope = wire + h.envelope[272:-32]
    h.envelope = envelope + hashlib.sha256(envelope + bytes(32)).digest()
    h.envelope_sha = hashlib.sha256(h.envelope).digest()
    # Pure schema validation is real C, while runtime peer/scope checks happen in the child.
    library.soc_envelope_validate.argtypes = [ctypes.c_char_p]
    h.approve(h.approval)
    with pytest.raises((ValueError, OSError, EOFError)):
        h.authenticate_fixture(AuthenticationFixture())
    assert h.ended and h.authentication == "REVOKED"


def test_user_cannot_forge_kernel_credentials():
    one, two = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with pytest.raises(PermissionError):
            one.sendmsg(
                [b"not-authority"],
                [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", os.getpid(), 0, 0))],
            )
    finally:
        one.close()
        two.close()


def test_privileged_fd_injection_is_closed_and_rejected(session):
    h, _ = session
    authenticate(h)
    old = h.channel
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    fd = os.open("/dev/null", os.O_RDONLY)
    h.channel = left
    # Deliver an ordinary FD; the same rule rejects any privileged FD without exposing it.
    right.sendmsg([b"bad"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
    try:
        with pytest.raises(ValueError, match="IDENTITY_CHANGED"):
            h._packet(uid=os.getuid(), gid=os.getgid())
    finally:
        h.channel = old
        left.close()
        right.close()
        os.close(fd)


def test_run_restart_outside_scope_is_denied_without_new_auth(session):
    from soc_agent.security_ai.ebpf_native.contracts import RunIdentity

    h, _ = session
    authenticate(h)
    run = RunIdentity(application_session=uuid4(), scope_digest="0" * 64, run_number=1)
    with pytest.raises(ValueError, match="RUN_SCOPE"):
        h.command(Command(command="ATTACH", plan_digest=h.plan.approval, sequence=1, run=run))
    assert h.authentication == "REVOKED"
