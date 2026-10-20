"""Installation fixtures never assert Root installation or Native qualification."""

import hashlib
import os

import pytest
from pydantic import ValidationError

from soc_agent.security_ai.ebpf_tc.release import (
    InstallationPlan,
    ReleaseEvidence,
    _directory,
    _open_file,
    installation_plan,
)


@pytest.mark.parametrize("path", ["../payload", "a/b", ".", "..", ""])
def test_installer_rejects_traversal(tmp_path, path):
    fd = os.open(tmp_path, os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="PATH_INVALID"):
            _open_file(fd, path, "a" * 64, 0o444, owner=os.getuid())
    finally:
        os.close(fd)


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "writable", "parent", "hash"])
def test_unprivileged_installation_attack_fixture(tmp_path, attack):
    path = tmp_path / "broker"
    path.write_bytes(b"reviewed artifact")
    path.chmod(0o444)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    if attack == "symlink":
        path.rename(tmp_path / "target")
        path.symlink_to("target")
    elif attack == "hardlink":
        os.link(path, tmp_path / "other")
    elif attack == "writable":
        path.chmod(0o666)
    elif attack == "parent":
        tmp_path.chmod(0o777)
    else:
        expected = "f" * 64
    fd = os.open(tmp_path, os.O_DIRECTORY)
    try:
        with pytest.raises((ValueError, OSError)):
            _open_file(fd, "broker", expected, 0o444, owner=os.getuid())
    finally:
        os.close(fd)


def test_verified_fd_is_not_reopened_after_path_swap(tmp_path):
    path = tmp_path / "broker"
    path.write_bytes(b"reviewed artifact")
    path.chmod(0o444)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    parent = os.open(tmp_path, os.O_DIRECTORY)
    fd = _open_file(parent, "broker", expected, 0o444, owner=os.getuid())
    try:
        path.rename(tmp_path / "held")
        path.symlink_to("/dev/null")
        assert os.pread(fd, 100, 0) == b"reviewed artifact"
    finally:
        os.close(fd)
        os.close(parent)


def test_root_owner_check_rejects_development_checkout(tmp_path):
    with pytest.raises(ValueError):
        _directory(tmp_path.stat(), 0)


def test_installation_plan_is_not_executable_permission_or_release(tmp_path):
    p = installation_plan(
        {n: "a" * 64 for n in ("bootstrap", "broker", "libnative-tc.so")}, "b" * 64
    )
    assert p.state == "UNPRIVILEGED_PLAN_NOT_INSTALLED" and not p.native_admission
    assert not list(tmp_path.iterdir())
    with pytest.raises(ValidationError):
        InstallationPlan.model_validate(p.model_dump() | {"destination": "/tmp/evil"})
    release = ReleaseEvidence(trusted_installation="VERIFIED", broker_ipc="VERIFIED").snapshot()
    assert release["state"] == "BLOCKED" and release["native_gate"] == "B2A_CLOSED"
    assert not release["automatic_attach"] and not release["authentication_restored"]


def test_journal_hardlink_and_orphan_never_restore_authority(tmp_path):
    from tests.unit.ebpf_tc.test_journal import row

    from soc_agent.security_ai.ebpf_tc.journal import recover_native

    path = tmp_path / "journal"
    path.write_bytes(row("a" * 64, "ATTACH_VERIFIED", 1, bytes(32)))
    recovered = recover_native(path, "a" * 64)
    assert recovered["state"] == "ORPHANED" and not recovered["automatic_attach"]
    os.link(path, tmp_path / "duplicate")
    with pytest.raises(ValueError, match="BOUND"):
        recover_native(path, "a" * 64)


def test_qualification_cli_only_prints_uninstalled_blocked_plan(monkeypatch, capsys):
    import json

    from soc_agent.security_ai.ebpf_tc import __main__ as cli
    from soc_agent.security_ai.ebpf_tc import bridge

    monkeypatch.setattr(
        bridge,
        "inspect_artifacts",
        lambda _: {n: "a" * 64 for n in ("bootstrap", "broker", "libnative-tc.so")},
    )
    monkeypatch.setattr(cli, "file_sha", lambda _: "b" * 64)
    assert cli.main(["qualify", "--artifacts", "/untrusted/staging", "--program", "/unused"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["release"]["state"] == "BLOCKED"
    assert printed["installation_plan"]["state"] == "UNPRIVILEGED_PLAN_NOT_INSTALLED"


def test_python_gate_override_cannot_execute_future_path(monkeypatch):
    from tests.unit.ebpf_tc.test_contracts import native_plan

    from soc_agent.security_ai.ebpf_tc import bridge

    monkeypatch.setattr(bridge, "native_admitted", lambda: True)
    with pytest.raises(ValueError, match="EXECUTION_BLOCKED"):
        bridge.native_handoff(native_plan(), 3, 4, 5)
