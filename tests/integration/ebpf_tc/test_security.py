"""Read-only C validators and ordinary-UID Unix IPC; no PAM/TC/BPF work."""

import array
import ctypes
import os
import socket
import subprocess

import pytest
from tests.unit.ebpf_tc.test_contracts import native_plan

from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.contracts import REQUEST


@pytest.fixture(scope="module")
def library(tmp_path_factory):
    directory = tmp_path_factory.mktemp("security-c")
    compile_native(directory)
    return ctypes.CDLL(str(directory / "libnative-tc.so")), directory


def wire(plan, **changes):
    fields = (
        dict(
            operation=3,
            sequence=1,
            generation=0,
            handle=0,
            reason=0,
            approval=bytes.fromhex(plan.approval),
            owner=bytes(56),
        )
        | changes
    )
    return REQUEST.pack(*fields.values())


@pytest.mark.parametrize(
    "change",
    [
        {"operation": 0},
        {"operation": 7},
        {"sequence": 0},
        {"sequence": 2},
        {"approval": bytes(32)},
        {"reason": 1},
        {"handle": 123},
        {"owner": b"x" * 56},
    ],
)
def test_malformed_replayed_and_unknown_command(library, change):
    lib, _ = library
    plan = native_plan()
    assert (
        lib.soc_request_validate(
            ctypes.create_string_buffer(plan.wire()),
            ctypes.create_string_buffer(wire(plan, **change)),
            0,
            0,
        )
        != 0
    )


def test_ipc_requires_kernel_credentials_and_rejects_rights(library):
    lib, _ = library
    plan = native_plan()
    for attack in ("none", "rights", "partial", "oversize", "missing_credentials"):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fd = os.open("/dev/null", os.O_RDONLY)
        try:
            if attack != "missing_credentials":
                left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            body = wire(plan)
            if attack == "partial":
                body = body[:-1]
            if attack == "oversize":
                body += b"x"
            ancillary = (
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))]
                if attack == "rights"
                else []
            )
            right.sendmsg([body], ancillary)
            rc = lib.soc_receive_request(
                left.fileno(),
                ctypes.create_string_buffer(plan.wire()),
                0,
                ctypes.create_string_buffer(112),
            )
            assert (rc == 0) == (attack == "none")
        finally:
            os.close(fd)
            left.close()
            right.close()


def test_credential_delegation_and_pid_reuse_rejected(library):
    lib, _ = library
    plan = native_plan()
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        pid = os.fork()
        if pid == 0:
            left.close()
            right.send(wire(plan))
            os._exit(0)
        os.waitpid(pid, 0)
        assert (
            lib.soc_receive_request(
                left.fileno(),
                ctypes.create_string_buffer(plan.wire()),
                0,
                ctypes.create_string_buffer(112),
            )
            != 0
        )
        damaged = bytearray(plan.wire())
        damaged[16] ^= 1
        assert lib.soc_peer(left.fileno(), ctypes.create_string_buffer(bytes(damaged))) != 0
    finally:
        left.close()
        right.close()


def test_command_rate_budget_never_sleeps_or_retries(library):
    lib, _ = library
    lib.soc_rate_allow.argtypes = [
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint64,
    ]
    slots, cursor = (ctypes.c_uint64 * 32)(), ctypes.c_uint32()
    for _ in range(32):
        assert lib.soc_rate_allow(slots, ctypes.byref(cursor), 1000000000) == 0
    assert lib.soc_rate_allow(slots, ctypes.byref(cursor), 1000000000) != 0
    assert lib.soc_rate_allow(slots, ctypes.byref(cursor), 2000000000) == 0
    assert lib.soc_rate_allow(slots, ctypes.byref(cursor), 1999999999) != 0


@pytest.mark.parametrize(
    "path", [b"/usr/../usr/bin/true", b"/usr//bin/true", b"/usr/./bin/true", b"relative"]
)
def test_c_trust_walker_rejects_noncanonical_path(library, path):
    lib, _ = library
    assert lib.soc_trusted(path, None) < 0


def test_no_custom_dso_before_or_after_privilege_transfer(library):
    _, directory = library
    for name in ("bootstrap", "broker"):
        dynamic = subprocess.check_output(["readelf", "-d", str(directory / name)], text=True)
        assert "libnative-tc" not in dynamic and "RPATH" not in dynamic and "RUNPATH" not in dynamic
        for key, val in {
            "LD_LIBRARY_PATH": "/tmp/untrusted",
            "PYTHONPATH": "/tmp/untrusted",
        }.items():
            env = {"PATH": "/usr/bin:/bin", key: val}
            run = subprocess.run([str(directory / name), "--native"], env=env, capture_output=True)
            assert run.returncode == 2 and b"EXECUTION_BLOCKED" in run.stderr


def test_inspection_sanitizes_preload_library_and_python_environment(
    library, tmp_path, monkeypatch
):
    import hashlib
    import json

    from soc_agent.security_ai.ebpf_tc.bridge import inspect_artifacts

    _, directory = library
    marker = tmp_path / "injection-executed"
    source = tmp_path / "injection.c"
    source.write_text(
        "#include <stdio.h>\n__attribute__((constructor)) static void inject(void) {"
        "FILE *f=fopen(" + json.dumps(str(marker)) + ',"w");if(f)fclose(f);}\n'
    )
    dso = tmp_path / "injection.so"
    subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(dso)], check=True)
    expected = {
        n: hashlib.sha256((directory / n).read_bytes()).hexdigest()
        for n in (
            "bootstrap",
            "broker",
            "libnative-tc.so",
            "tc-fixture",
            "tcx-dispatch-fixture",
            "tcx.bpf.o",
        )
    }
    monkeypatch.setenv("LD_PRELOAD", str(dso))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    assert inspect_artifacts(directory, expected) == expected
    assert not marker.exists()


@pytest.mark.parametrize("offset", [0, 35, 80, 191])
def test_journal_corruption_cannot_restore_or_authorize(offset, tmp_path):
    from tests.unit.ebpf_tc.test_journal import row

    from soc_agent.security_ai.ebpf_tc.journal import recover_native

    body = bytearray(row("a" * 64, "BROKER_READY", 1, bytes(32)))
    body[offset] ^= 1
    path = tmp_path / "journal"
    path.write_bytes(body)
    with pytest.raises((ValueError, UnicodeDecodeError)):
        recover_native(path, "a" * 64)
