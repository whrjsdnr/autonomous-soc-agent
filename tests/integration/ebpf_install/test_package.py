"""Real compiler/readelf/filesystem fixtures; no root, PAM, BPF syscall or TC operation."""

import hashlib
import json
import os
import shutil

import pytest

from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.dependencies import read_held
from soc_agent.security_ai.ebpf_tc.install_simulation import InstallationSimulation, _publish
from soc_agent.security_ai.ebpf_tc.installation import (
    canonical,
    create_package,
    installation_plan,
    native_install,
    verify_package,
)
from soc_agent.security_ai.ebpf_tc.release import _directory


@pytest.fixture(scope="module")
def release(tmp_path_factory):
    directory = tmp_path_factory.mktemp("trusted-release")
    compile_native(directory / "build")
    manifest = create_package(directory / "build", directory / "package", "0.2.5")
    return directory, manifest


def clone(release, tmp_path):
    directory, manifest = release
    path = tmp_path / "package"
    shutil.copytree(directory / "package", path)
    return path, manifest


def rewrite(path, manifest, **changes):
    value = manifest.model_dump(mode="json") | changes
    body = canonical(value)
    file = path / "release.json"
    file.chmod(0o644)
    file.write_bytes(body)
    return hashlib.sha256(body).hexdigest()


def test_real_package_manifest_external_anchor_and_blocked_native_plan(release):
    directory, manifest = release
    assert verify_package(directory / "package", manifest.identity) == manifest
    assert len(manifest.dependencies) >= 6
    assert all(d.path.startswith("/usr/lib") for d in manifest.dependencies)
    plan = installation_plan(manifest)
    assert "RENAMEAT2_EXCHANGE_COMPLETE_FIXED_DIRECTORY" in plan["steps"]
    assert not plan["native_activation"] and not plan["automatic_rollback"]
    assert manifest.native_release == "BLOCKED" and manifest.dynamic_dependency_closure.startswith(
        "UNKNOWN"
    )
    assert manifest.payloads["bootstrap"].mode == 0o4755
    assert (directory / "package/bootstrap").stat().st_mode & 0o7777 == 0o444
    with pytest.raises(ValueError, match="APPROVAL"):
        native_install()


@pytest.mark.parametrize(
    "attack",
    [
        "manifest",
        "binary",
        "symlink",
        "hardlink",
        "parent",
        "traversal",
        "open_gate",
        "dependency",
        "missing_dependency",
        "binary_manifest",
    ],
)
def test_package_adversarial_cases(release, tmp_path, attack):
    path, manifest = clone(release, tmp_path)
    expected = manifest.identity
    broker = path / "broker"
    if attack == "manifest":
        rewrite(path, manifest, version="0.2.6")  # Old external anchor remains authoritative.
    elif attack == "binary":
        broker.chmod(0o644)
        broker.write_bytes(broker.read_bytes() + b"x")
    elif attack == "symlink":
        broker.rename(path / "foreign")
        broker.symlink_to("foreign")
    elif attack == "hardlink":
        os.link(broker, path / "other")
    elif attack == "parent":
        path.chmod(0o777)
    elif attack == "traversal":
        value = manifest.model_dump(mode="json")["payloads"]
        value["../broker"] = value.pop("broker")
        expected = rewrite(path, manifest, payloads=value)
    elif attack == "open_gate":
        expected = rewrite(path, manifest, native_release="VERIFIED")
    elif attack in ("dependency", "missing_dependency"):
        deps = manifest.model_dump(mode="json")["dependencies"]
        if attack == "dependency":
            deps[0]["sha256"] = "f" * 64
        else:
            deps.pop()
        expected = rewrite(path, manifest, dependencies=deps)
    else:
        f = path / "manifest.bin"
        f.chmod(0o644)
        f.write_bytes(b"bad")
    with pytest.raises((ValueError, OSError)):
        verify_package(path, expected)


def test_simulation_install_update_explicit_rollback_and_recovery(release, tmp_path):
    path, old = clone(release, tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    sim = InstallationSimulation(state)
    try:
        assert sim.activate(path, old.identity)["state"] == "FIXTURE_VERIFIED"
        with pytest.raises(ValueError, match="REUSE"):
            sim.activate(path, old.identity)
        expected = rewrite(path, old, version="0.2.6")
        # A new JSON version cannot reuse an old execution manifest.
        with pytest.raises(ValueError, match="EXECUTION_MANIFEST_MISMATCH"):
            verify_package(path, expected)
        from soc_agent.security_ai.ebpf_tc.installation import ReleaseManifest
        from soc_agent.security_ai.ebpf_tc.trust import execution_manifest

        updated = ReleaseManifest.model_validate_json((path / "release.json").read_bytes())
        descriptor = path / "release.trust"
        descriptor.chmod(0o644)
        descriptor.write_bytes(execution_manifest(updated))
        descriptor.chmod(0o444)
        current = verify_package(path, expected)
        assert sim.activate(path, current.identity)["active_manifest"] == expected
        with pytest.raises(ValueError, match="MANIFEST_MISMATCH"):
            sim.activate(path, old.identity, rollback=True)
        assert (
            sim.activate(state / old.identity, old.identity, rollback=True)["active_manifest"]
            == old.identity
        )
    finally:
        sim.close()
    recovered = InstallationSimulation(state)
    try:
        value = recovered.recover()
        assert value["source"] == "INSTALLATION_SIMULATION_NOT_ROOT"
        assert value["native_release"] == "BLOCKED" and not value["authentication_restored"]
        assert not value["automatic_attach"] and not value["automatic_inference"]
        assert (state / old.identity).is_dir() and (state / expected).is_dir()
    finally:
        recovered.close()


def test_crash_after_atomic_selector_requires_review_not_automatic_rollback(
    release, tmp_path, monkeypatch
):
    path, manifest = clone(release, tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    sim = InstallationSimulation(state)
    original = sim._journal

    def crash(kind, release):
        if kind == "RELEASE_COMMITTED":
            raise OSError("fixture interrupted commit")
        original(kind, release)

    monkeypatch.setattr(sim, "_journal", crash)
    try:
        with pytest.raises(OSError):
            sim.activate(path, manifest.identity)
        assert sim.recover()["state"] == "CRASH_REVIEW_REQUIRED"
        with pytest.raises(ValueError, match="CRASH_REVIEW_REQUIRED"):
            sim.activate(path, manifest.identity)
    finally:
        sim.close()


def test_atomic_publish_never_replaces_existing_directory(tmp_path):
    (tmp_path / "staged").mkdir()
    (tmp_path / "old").mkdir()
    fd = os.open(tmp_path, os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            _publish(fd, "staged", "old")
        assert (tmp_path / "staged").exists() and (tmp_path / "old").exists()
    finally:
        os.close(fd)


def test_held_snapshot_survives_path_swap_and_root_contract_rejects_user(
    release, tmp_path, monkeypatch
):
    path, manifest = clone(release, tmp_path)
    original = os.pread

    def swap(fd, count, offset):
        result = original(fd, count, offset)
        broker = path / "broker"
        if count == broker.stat().st_size + 1 and broker.exists():
            broker.rename(path / "retained")
            broker.symlink_to("/dev/null")
        return result

    monkeypatch.setattr(os, "pread", swap)
    with pytest.raises(ValueError, match="CHANGED"):
        read_held((path / "broker").absolute(), owner=os.getuid())
    with pytest.raises(ValueError):
        _directory(path.stat(), 0)


def test_dependency_inspection_does_not_execute_injected_library(release, tmp_path, monkeypatch):
    import subprocess

    directory, manifest = release
    marker = tmp_path / "injection"
    source = tmp_path / "inject.c"
    source.write_text(
        "#include <stdio.h>\n__attribute__((constructor)) void x(void){FILE *f=fopen("
        + json.dumps(str(marker))
        + ',"w");if(f)fclose(f);}'
    )
    library = tmp_path / "inject.so"
    subprocess.run(["cc", "-shared", "-fPIC", str(source), "-o", str(library)], check=True)
    monkeypatch.setenv("LD_PRELOAD", str(library))
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))
    verify_package(directory / "package", manifest.identity)
    assert not marker.exists()


def test_append_only_simulation_journal_corruption_is_not_recovered(release, tmp_path):
    path, manifest = clone(release, tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    sim = InstallationSimulation(state)
    try:
        sim.activate(path, manifest.identity)
        journal = state / "journal.jsonl"
        old = journal.read_bytes()
        journal.write_bytes(old[:-3] + b"bad")
        with pytest.raises(ValueError):
            sim.recover()
    finally:
        sim.close()


def test_rpath_is_rejected_without_running_the_elf(tmp_path):
    import subprocess

    from soc_agent.security_ai.ebpf_tc.dependencies import elf_metadata

    source = tmp_path / "library.c"
    source.write_text("int value(void){return 1;}")
    library = tmp_path / "library.so"
    subprocess.run(
        ["cc", "-shared", "-fPIC", str(source), "-Wl,-rpath,/tmp/untrusted", "-o", str(library)],
        check=True,
    )
    with pytest.raises(ValueError, match="SEARCH_PATH_DENIED"):
        elf_metadata(library.read_bytes())


def test_disk_budget_preserves_prior_evidence(release, tmp_path, monkeypatch):
    path, manifest = clone(release, tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    sim = InstallationSimulation(state)
    for n in range(8):
        (state / (str(n) * 64)).mkdir()
    try:
        with pytest.raises(ValueError, match="DISK_BUDGET"):
            sim.activate(path, manifest.identity)
        assert len(list(state.iterdir())) == 9
    finally:
        sim.close()


def test_cli_host_and_package_verification_never_activate_release(release, capsys):
    from soc_agent.security_ai.ebpf_tc.__main__ import main

    directory, manifest = release
    assert (
        main(
            [
                "verify-package",
                "--package",
                str(directory / "package"),
                "--manifest-sha",
                manifest.identity,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["native_release"] == "BLOCKED"
    assert main(["qualify-host"]) == 0
    assert json.loads(capsys.readouterr().out)["facts"]["tcx_native"] == "NOT_PROBED"


def test_manifest_exact_readonly_mode_contract(tmp_path):
    from soc_agent.security_ai.ebpf_tc.release import _open_file

    path = tmp_path / "release.json"
    path.write_bytes(b"manifest")
    path.chmod(0o644)
    parent = os.open(tmp_path, os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError, match="FILE_UNTRUSTED"):
            _open_file(
                parent,
                "release.json",
                hashlib.sha256(b"manifest").hexdigest(),
                0o444,
                owner=os.getuid(),
            )
    finally:
        os.close(parent)


def test_simulation_never_overwrites_foreign_evidence(tmp_path):
    directory = tmp_path / "foreign"
    directory.mkdir(mode=0o700)
    evidence = directory / "active.json"
    evidence.write_bytes(b"existing user evidence")
    with pytest.raises(ValueError, match="FOREIGN_DIRECTORY"):
        InstallationSimulation(directory)
    assert evidence.read_bytes() == b"existing user evidence"
