"""Exercise the actual C receive path with kernel SCM credentials and FD accounting."""

import array
import ctypes
import fcntl
import os
import socket

import pytest
from tests.ebpf_broker_support import plan as broker_plan

from soc_agent.security_ai.ebpf_tc.contracts import NativePlan
from soc_agent.security_ai.ebpf_tc.trust import release_approval


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "unsealed",
        "extra_fd",
        "short",
        "manifest",
        "approval",
        "audit_not_append",
        "audit_nonempty",
    ],
)
def test_c_receive_closes_rejected_rights_and_checks_seals(release, tmp_path, case):
    root, _, manifest = release
    broker = broker_plan()
    scope = broker.application.scope.model_copy(
        update={"program_sha256": manifest.payloads["tc.bpf.o"].sha256}
    )
    broker = broker.model_copy(
        update={"application": broker.application.model_copy(update={"scope": scope})}
    )
    plan = NativePlan(
        broker=broker,
        bootstrap_sha256=manifest.payloads["bootstrap"].sha256,
        native_broker_sha256=manifest.payloads["broker"].sha256,
        loader_sha256=manifest.payloads["libnative-tc.so"].sha256,
        program_sha256=manifest.payloads["tc.bpf.o"].sha256,
        bundle_digest=manifest.bundle_digest,
        mode="B2D_TCX_BLOCKED",
    )
    envelope = release_approval(plan, manifest)
    one, two = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    two.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    fd = os.memfd_create("fixture-approval", os.MFD_ALLOW_SEALING)
    os.write(fd, envelope)
    if case != "unsealed":
        fcntl.fcntl(fd, 1033, 15)
    audit = os.open(
        tmp_path / "audit",
        os.O_RDWR | os.O_CREAT | (0 if case == "audit_not_append" else os.O_APPEND),
        0o600,
    )
    if case == "audit_nonempty":
        os.write(audit, b"prior-evidence")
    rights = array.array("i", [fd, audit] + ([fd] if case == "extra_fd" else []))
    approval, release_sha = envelope[-32:], bytes.fromhex(manifest.identity)
    if case == "approval":
        approval = bytes(32)
    if case == "manifest":
        release_sha = bytes(32)
    library = ctypes.CDLL(str(root / "build/libnative-tc.so"))
    library.soc_handoff_receive.argtypes = [
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    body = ctypes.create_string_buffer(352)
    plan_out, audit_out = ctypes.c_int(-1), ctypes.c_int(-1)
    before = len(os.listdir("/proc/self/fd"))
    try:
        one.sendmsg(
            [envelope[:-1] if case == "short" else envelope],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        )
        result = library.soc_handoff_receive(
            two.fileno(),
            os.getuid(),
            os.getgid(),
            broker.application.application_session.bytes,
            approval,
            release_sha,
            body,
            ctypes.byref(plan_out),
            ctypes.byref(audit_out),
        )
        if case == "valid":
            assert result == 0 and body.raw == envelope
            os.close(plan_out.value)
            os.close(audit_out.value)
        else:
            assert result != 0 and plan_out.value == audit_out.value == -1
        assert len(os.listdir("/proc/self/fd")) == before
    finally:
        one.close()
        two.close()
        os.close(fd)
        os.close(audit)
