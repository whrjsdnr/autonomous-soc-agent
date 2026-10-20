"""Small ordinary-UID installer and authentication-boundary qualification suite."""

import base64
import hashlib
import json
import os
import socket
import stat
import subprocess
from types import SimpleNamespace

import pytest

from soc_agent.security_ai.ebpf_tc.auth_session import AuthenticationQualification
from soc_agent.security_ai.ebpf_tc.build import AUTH_POLICY, compile_native
from soc_agent.security_ai.ebpf_tc.install_engine import _apply
from soc_agent.security_ai.ebpf_tc.password_policy import validate_pam_inputs


def image():
    names = [
        "entry",
        "bootstrap",
        "broker",
        "libnative-tc.so",
        "tc.bpf.o",
        "manifest.bin",
        "pam-policy.conf",
        "release.json",
        "release.trust",
    ]
    rows = {}
    for name in names:
        body = ("fixture-not-executable:" + name).encode()
        rows[name] = dict(
            body=base64.b64encode(body).decode(),
            sha256=hashlib.sha256(body).hexdigest(),
            mode=0o555 if name in names[:3] else 0o444,
        )
    return dict(files=rows, manifest_sha256=rows["release.json"]["sha256"])


def apply(tmp_path, value, action):
    fd = os.open(tmp_path, os.O_DIRECTORY | os.O_RDONLY)
    try:
        return _apply(value, fd, os.getuid(), action)
    finally:
        os.close(fd)


def test_installer_dry_run_and_integrity(tmp_path):
    value = image()
    assert apply(tmp_path, value, "install")["native_activation"] is False
    apply(tmp_path, value, "check")
    for name, row in value["files"].items():
        path = tmp_path / "soc-agent-ebpf" / name
        assert stat.S_IMODE(path.stat().st_mode) == row["mode"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]


def test_manifest_or_payload_mismatch_does_not_publish(tmp_path):
    value = image()
    value["files"]["broker"]["body"] = base64.b64encode(b"modified").decode()
    with pytest.raises(ValueError, match="INSTALL_IMAGE_HASH"):
        apply(tmp_path, value, "install")
    assert list(tmp_path.iterdir()) == []
    value = image()
    value["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="INSTALL_MANIFEST_MISMATCH"):
        apply(tmp_path, value, "install")


def test_conflict_and_exact_rollback_preserve_foreign_paths(tmp_path):
    value = image()
    apply(tmp_path, value, "install")
    with pytest.raises(ValueError, match="INSTALL_CONFLICT"):
        apply(tmp_path, value, "install")
    folder = tmp_path / "soc-agent-ebpf"
    (folder / "foreign").write_text("preserve")
    with pytest.raises(ValueError, match="INSTALL_FILE_SET_MISMATCH"):
        apply(tmp_path, value, "rollback")
    assert (folder / "foreign").read_text() == "preserve"
    (folder / "foreign").unlink()  # Remove only the test-owned injected fixture.
    apply(tmp_path, value, "rollback")
    assert not folder.exists()
    assert (tmp_path / (".soc-agent-ebpf.rollback-" + value["manifest_sha256"]) / "broker").exists()


def test_installer_symlink_and_hardlink_rejection(tmp_path):
    value = image()
    (tmp_path / "soc-agent-ebpf").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="INSTALL_CONFLICT"):
        apply(tmp_path, value, "install")
    (tmp_path / "soc-agent-ebpf").unlink()
    apply(tmp_path, value, "install")
    os.link(tmp_path / "soc-agent-ebpf/broker", tmp_path / "extra-link")
    with pytest.raises(ValueError, match="INSTALL_FILE_UNTRUSTED"):
        apply(tmp_path, value, "check")


def test_pam_policy_change_or_bypass_is_not_qualified():
    inputs = {key: path.read_text() for key, path in AUTH_POLICY.items()}
    validate_pam_inputs(inputs)
    inputs["SOC_AUTH_COMMON_SHA"] = "auth required pam_permit.so\n"
    with pytest.raises(ValueError, match="OS_AUTH_PAM_POLICY_UNSUPPORTED"):
        validate_pam_inputs(inputs)


def test_authentication_purpose_is_distinct_and_cannot_load():
    auth = object.__new__(AuthenticationQualification)
    auth.envelope = bytes(range(256)) + bytes(96)
    assert auth.approval != auth.envelope[-32:].hex()
    auth.qualification_only = True
    with pytest.raises(ValueError, match="AUTH_QUALIFICATION_NO_KERNEL_ACTION"):
        auth.command(SimpleNamespace(command="ATTACH"))
    with pytest.raises(ValueError, match="NO_FIXTURE_IMPERSONATION"):
        auth.authenticate_fixture()


def test_authentication_replay_and_expiration_fail_closed():
    auth = object.__new__(AuthenticationQualification)
    auth.state, auth.attempted, auth.ended = "AUTHENTICATION_REQUIRED", True, False
    with pytest.raises(ValueError, match="AUTH_QUALIFICATION_REPLAY"):
        auth.authenticate_native()
    auth.state, auth.qualification_only = "CLOSED", True
    with pytest.raises(ValueError, match="HANDOFF_SESSION_NOT_READY"):
        auth.command(SimpleNamespace(command="STATUS"))


def test_real_unprivileged_peer_cannot_claim_root_handoff():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    auth = object.__new__(AuthenticationQualification)
    auth.listener = SimpleNamespace(accept=lambda: (a, None), close=lambda: None)
    auth.plan = SimpleNamespace(broker=SimpleNamespace(uid=os.getuid(), gid=os.getgid()))
    try:
        with pytest.raises(ValueError, match="HANDOFF_PEER_CREDENTIALS"):
            auth._bind(fixture=False)
    finally:
        a.close()
        b.close()


def test_compiled_auth_entry_denies_unprivileged_execution_and_preserves_kernel_gate(tmp_path):
    hashes = compile_native(tmp_path / "build")
    assert hashes["tcx.bpf.o"] == "928a8afc1a75ce97acef5edaa6b5bb8823b681a0784bed7e067fc9f90cf50e4a"
    bootstrap = tmp_path / "build/bootstrap"
    inspected = subprocess.run(
        [str(bootstrap), "--inspect"], capture_output=True, text=True, check=True
    )
    assert json.loads(inspected.stdout)["native_gate"] is False
    args = [
        str(bootstrap),
        "--auth-qualification",
        str(os.getuid()),
        str(os.getgid()),
        "1" * 32,
        "2" * 64,
        "3" * 64,
        "4" * 64,
    ]
    denied = subprocess.run(args, capture_output=True, text=True)
    assert denied.returncode == 2 and "OS_AUTH_QUALIFICATION_REJECTED" in denied.stderr
    assert subprocess.run([str(bootstrap), "--os-handoff"], capture_output=True).returncode == 2
    args[1] = "--live-qualification"
    assert subprocess.run(args, capture_output=True).returncode == 2
    import ctypes

    library = ctypes.CDLL(str(tmp_path / "build/libnative-tc.so"))
    assert library.soc_qualification_admit(-1, None, 1) != 0
    assert library.soc_native_gate() == 0

    from tests.ebpf_broker_support import controller

    from soc_agent.security_ai.ebpf_tc.bridge import Preparation
    from soc_agent.security_ai.ebpf_tc.installation import create_package

    release = create_package(tmp_path / "build", tmp_path / "package", "0.4.2")
    owner = controller(tmp_path / "application", authenticate=False)
    prep = Preparation(owner, tmp_path / "build")
    try:
        handoff = prep.os_auth_handoff(
            tmp_path / "package", release.identity, live_qualification=True
        )
        assert handoff.data.approval == handoff.envelope[-32:].hex()
        assert handoff.data.approval != handoff.approval
    finally:
        if prep._os_handoff:
            prep._os_handoff.close()
        owner.close()


def test_counter_snapshot_zero_is_not_unknown_or_kernel_drop(tmp_path):
    import struct

    from tests.unit.ebpf_tc.test_contracts import native_plan
    from tests.unit.tcx_data.test_channel import frame

    from soc_agent.security_ai.ebpf_native.contracts import local_controller
    from soc_agent.security_ai.ebpf_tc.data_plane import PacketChannel

    channel = PacketChannel(native_plan(), "f" * 64, tmp_path)
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    channel.channel, channel.identity, channel.source = left, local_controller(), 2
    try:
        channel.prepare_adapter(7)
        counter = struct.pack("<QQ7QII", 7, 1000, *([0] * 7), 1, 0)
        right.send(frame(channel, kind=5, packet=counter))
        channel.pump()
        evidence = channel.snapshot()
        assert evidence["counter_evidence"]["retrieval"] == "SUCCESS"
        assert evidence["counter_evidence"]["source"] == "FIXTURE_COUNTER_NEVER_NATIVE"
        assert evidence["ring_loss"] == 0 and evidence["kernel_drops"] is None
        right.send(frame(channel, kind=5, sequence=2, packet=counter))
        with pytest.raises(ValueError, match="TCX_COUNTER_EVIDENCE_SCHEMA"):
            channel.pump()
    finally:
        channel.close()
        right.close()


def test_auth_failure_does_not_retry_or_leave_session_authority(tmp_path, monkeypatch):
    import soc_agent.security_ai.ebpf_tc.auth_session as module

    auth = object.__new__(AuthenticationQualification)
    auth.state, auth.attempted, auth.ended = "AUTHENTICATION_REQUIRED", False, False
    auth.release = object()
    auth.plan = SimpleNamespace(broker=SimpleNamespace(uid=os.getuid()))
    auth.error, auth.channel, auth.listener, auth.child = None, None, None, None
    auth.audit_fd, auth.deadline = -1, None
    auth.qualification_only = True
    auth.data = SimpleNamespace(close=lambda: None)
    auth._scope = lambda: None
    auth._event = lambda *args, **kwargs: None
    auth.snapshot = lambda: {"state": auth.state}
    auth.sudo_command = lambda: ("/usr/bin/sudo", "-k", "--", "FIXED_QUALIFICATION_ONLY")
    monkeypatch.setattr(module, "validate_root_release", lambda _: None)
    tty = tmp_path / "tty-fixture"
    tty.write_bytes(b"")
    original_open = os.open
    monkeypatch.setattr(module.os, "open", lambda *args, **kwargs: original_open(tty, os.O_RDWR))
    monkeypatch.setattr(module.os, "isatty", lambda _: True)
    monkeypatch.setattr(module.os, "tcgetpgrp", lambda _: os.getpgrp())
    calls = []

    def denied(*args, **kwargs):
        calls.append(args)
        raise PermissionError("mock-only")

    monkeypatch.setattr(module.subprocess, "Popen", denied)
    with pytest.raises(PermissionError):
        auth.authenticate_native()
    assert len(calls) == 1 and auth.authentication == "REVOKED" and auth.ended
    assert auth.state == "ERROR" and auth.deadline is None


def test_compiled_sudo_policy_rejects_nopasswd_and_authentication_exemptions(tmp_path):
    from soc_agent.security_ai.ebpf_tc.build import ROOT

    driver = tmp_path / "policy-test.c"
    driver.write_text(
        '#include "auth_qualification.c"\n'
        "int __wrap_soc_trusted(const char *p,const uint8_t *h) {"
        "(void)h;if(!getuid())return -1;return open(p,O_RDONLY|O_NOFOLLOW);}\n"
        "int main(int n,char **v) {if(!getuid() || n!=2)return 2;"
        "return sudoers_file(v[1],1)?2:0;}\n"
    )
    executable = tmp_path / "policy-test"
    subprocess.run(
        [
            "cc",
            "-I" + str(ROOT),
            str(driver),
            *[str(ROOT / name) for name in ("core.c", "os.c", "trust.c", "handoff.c")],
            "-Wl,--wrap=soc_trusted",
            "-lcrypto",
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    policy = tmp_path / "sudoers-fixture"
    policy.write_text("Defaults env_reset\n%sudo ALL=(ALL:ALL) ALL\n")
    assert subprocess.run([str(executable), str(policy)]).returncode == 0
    for bad in (
        "%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n",
        "Defaults !authenticate\n",
        "Defaults exempt_group=sudo\n",
    ):
        policy.write_text(bad)
        assert subprocess.run([str(executable), str(policy)]).returncode == 2
