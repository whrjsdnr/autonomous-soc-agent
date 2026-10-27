"""Real ordinary-UID files and temporary ledgers, never Root/Native."""

import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import activate_fixture, artifact, h
from tests.unit.ebpf_tc.test_r1r2_operational import review as review
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import runtime_recovery as recovery
from soc_agent.security_ai.ebpf_tc.build import compile_native
from soc_agent.security_ai.ebpf_tc.installation import canonical, create_package
from soc_agent.security_ai.ebpf_tc.reassessment_admission import preview_reservation
from soc_agent.security_ai.ebpf_tc.release import _open_file
from soc_agent.security_ai.native_campaign import NativeCampaign


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    root = tmp_path_factory.mktemp("recovery-package")
    compile_native(root / "artifacts")
    release = create_package(root / "artifacts", root / "package", "0.6.3")
    return root / "package", release


@pytest.fixture
def retained(tmp_path, monkeypatch, package):
    source, release = package
    destination = tmp_path / "installed"
    shutil.copytree(source, destination)
    for name, payload in release.payloads.items():
        (destination / name).chmod(payload.mode)
    for name in ("release.json", "release.trust"):
        (destination / name).chmod(0o444)
    monkeypatch.setattr(recovery, "INSTALL", destination)
    # Only fixtures substitute ownership. SHA/mode/nlink/FD checks are real.
    monkeypatch.setattr(recovery, "_directory", lambda st, owner: None)
    monkeypatch.setattr(recovery, "_open_file", lambda *a: _open_file(*a, owner=os.getuid()))
    return destination, release


def test_retention_real_files_does_not_claim_runtime(retained):
    _, release = retained
    before = release.model_dump_json()
    result = recovery.inspect_retained(release.identity)
    assert len(result.files) == 9
    assert result.dependencies == release.dependencies
    assert not result.runtime_qualified and not result.native_admission
    assert release.model_dump_json() == before


@pytest.mark.parametrize("attack", ["sha", "mode", "hardlink", "symlink", "extra", "missing"])
def test_retention_tamper_rejected(retained, attack):
    root, release = retained
    target = root / "broker"
    if attack == "sha":
        target.chmod(0o644)
        target.write_bytes(b"tampered")
        target.chmod(0o555)
    elif attack == "mode":
        target.chmod(0o777)
    elif attack == "hardlink":
        os.link(target, root.parent / "other-link")
    elif attack == "symlink":
        target.unlink()
        target.symlink_to(root / "entry")
    elif attack == "extra":
        (root / "extra").write_bytes(b"unexpected")
    else:
        target.unlink()
    with pytest.raises((ValueError, OSError)):
        recovery.inspect_retained(release.identity)


def test_rollback_integrity_uses_distinct_fixed_identity(retained):
    root, release = retained
    archive = root.parent / (".soc-agent-ebpf.rollback-" + release.identity)
    shutil.copytree(root, archive)
    assert recovery.inspect_retained(release.identity, rollback=True).directory == str(archive)
    (archive / "release.trust").unlink()
    with pytest.raises(ValueError):
        recovery.inspect_retained(release.identity, rollback=True)
    assert recovery.inspect_retained(release.identity).manifest == release.identity


def abi_report(release):
    zlib = next(d for d in release.dependencies if d.soname == "libz.so.1")
    return dict(
        status="STATIC_AND_BOUNDED_SMOKE_COMPATIBLE_FOR_OBSERVED_CONSUMERS",
        libraries=dict(old=dict(sha256="8" * 64), new=dict(path=zlib.path, sha256=zlib.sha256)),
        consumer_requirements={
            d.path: dict(sha256=d.sha256, missing_in_new=[])
            for d in release.dependencies
            if d.soname in {"libbpf.so.1", "libelf.so.1"}
        },
        missing_old_exports=[],
        changed_abi_export_metadata={},
        headers={
            n: dict(identical=True, old_sha256="1" * 64, new_sha256="1" * 64)
            for n in ("zlib.h", "zconf.h")
        },
        smoke=dict(old=dict(status="PASS"), new=dict(status="PASS")),
    )


@pytest.mark.parametrize(
    "attack", ["none", "sha", "zlib", "consumer", "abi", "unknown", "malformed"]
)
def test_pinned_abi_evidence_cannot_replace_dependency_hash(package, tmp_path, attack):
    _, release = package
    data = abi_report(release)
    if attack == "zlib":
        data["libraries"]["new"]["sha256"] = "f" * 64
    elif attack == "consumer":
        data["consumer_requirements"] = {}
    elif attack == "abi":
        data["missing_old_exports"] = ["inflate"]
    elif attack == "unknown":
        data["smoke"]["new"]["status"] = "UNKNOWN"
    elif attack == "malformed":
        data.pop("libraries")
    p = tmp_path / "abi.json"
    p.write_bytes(canonical(data))
    sha = "0" * 64 if attack == "sha" else h(p.read_bytes())
    if attack == "none":
        assert recovery.verify_abi(p, sha, release).result == "OBSERVED_COMPATIBLE_LIMITED"
    else:
        with pytest.raises(ValueError):
            recovery.verify_abi(p, sha, release)


def preview_inputs(review, stable):
    adapter, path, scope, dns = activate_fixture(review, stable)
    a = artifact()
    return adapter, dict(
        directory=adapter.directory,
        amendment_file=adapter.directory / "FIXTURE_amendment.json",
        amendment_sha=adapter.amendment_sha,
        identity=dict(
            manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
        ),
        scope=scope,
        dns_scope=dns,
        approval_file=path,
        approval_sha=h(path.read_bytes()),
        root_cost=1,
        git_commit=a.git_commit,
    )


def test_real_admission_preview_does_not_reserve_or_consume_receipt(review, stable):
    adapter, kwargs = preview_inputs(review, stable)
    path = adapter.directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    for _ in range(2):
        result = preview_reservation(**kwargs)
        assert result["status"] == "PREVIEW_ONLY_NOT_RESERVED"
        assert result["native_admission"] is False
        assert result["native_used_if_reserved"] == 2
        assert path.read_bytes() == before
    adapter.reserve(
        kwargs["identity"],
        kwargs["scope"],
        kwargs["dns_scope"],
        kwargs["approval_file"],
        kwargs["approval_sha"],
        root_cost=1,
    )
    after = path.read_bytes()
    with pytest.raises(ValueError):
        preview_reservation(**kwargs)
    assert path.read_bytes() == after


@pytest.mark.parametrize("attack", ["missing", "sha", "session", "release", "stale", "policy"])
def test_real_approval_validator_failures_no_append(review, stable, attack):
    adapter, kwargs = preview_inputs(review, stable)
    ledger = adapter.directory / "execution-ledger.jsonl"
    p = kwargs["approval_file"]
    if attack == "missing":
        p.unlink()
    elif attack == "sha":
        kwargs["approval_sha"] = "0" * 64
    elif attack in {"session", "release"}:
        data = json.loads(p.read_bytes())
        if attack == "session":
            data["next_session"] = "wrong"
        else:
            data["release"]["image"] = "0" * 64
        p.write_bytes(canonical(data))
        kwargs["approval_sha"] = h(p.read_bytes())
    elif attack == "stale":
        NativeCampaign._locked(adapter, lambda rows: dict(event="FIXTURE_OTHER_EVENT"))
    else:
        p = kwargs["amendment_file"]
        data = json.loads(p.read_bytes()) | dict(decision="NOT_APPROVED")
        p.write_bytes(canonical(data))
        kwargs["amendment_sha"] = h(p.read_bytes())
    before = ledger.read_bytes()
    with pytest.raises((ValueError, OSError)):
        preview_reservation(**kwargs)
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("bad_stage", [None, "preservation", "runtime"])
def test_combined_readiness_reports_stages_independently(monkeypatch, bad_stage):
    def fail():
        raise ValueError("FIXTURE_MISMATCH")

    monkeypatch.setattr(
        recovery,
        "inspect_retained",
        lambda *a: fail() if bad_stage == "preservation" else SimpleNamespace(),
    )
    monkeypatch.setattr(
        recovery,
        "validate_runtime",
        lambda *a: fail() if bad_stage == "runtime" else SimpleNamespace(),
    )
    result = recovery.execution_readiness(Path("/unused"), "1" * 64, installed_manifest="2" * 64)
    assert result["status"] == "BLOCKED" and not result["native_admission"]
    for name in ("preservation", "runtime"):
        assert result["stages"][name]["status"] == (
            "FAILED" if name == bad_stage else "VERIFIED_READ_ONLY_NOT_EXECUTION"
        )


@pytest.mark.parametrize("attack", ["none", "image", "manifest", "dependency", "host", "bundle"])
def test_runtime_validator_real_package_and_artifact_tampering(
    package, tmp_path, monkeypatch, attack
):
    source, release = package
    shutil.copytree(source, tmp_path / "release")
    body = b"raise SystemExit('RECOVERY_POLICY_NOT_ACTIVATED')\n"
    image = tmp_path / "quarantined-image.py"
    image.write_bytes(body)
    image.chmod(0o400)
    monkeypatch.setattr(recovery, "host_identity", lambda: {"fixture": "fixed"})
    candidate = recovery.RuntimeCandidate(
        root_manifest=release.identity,
        bundle=h(canonical(recovery.phase_d.runtime_bundle())),
        source_snapshot="1" * 64,
        image=h(body),
        abi=recovery.AbiEvidence(
            report_sha="2" * 64,
            old_zlib="3" * 64,
            current_zlib="4" * 64,
            result="OBSERVED_COMPATIBLE_LIMITED",
        ),
        host={"fixture": "fixed"},
        dependencies=release.dependencies,
    )
    data = candidate.model_dump(mode="json")
    if attack == "image":
        image.chmod(0o600)
        image.write_bytes(body + b"# changed\n")
        image.chmod(0o400)
    elif attack == "dependency":
        data["dependencies"][0]["sha256"] = "f" * 64
    elif attack == "host":
        data["host"] = {"fixture": "different"}
    elif attack == "bundle":
        data["bundle"] = "f" * 64
    meta = tmp_path / "runtime-recovery.json"
    meta.write_bytes(canonical(data))
    sha = "f" * 64 if attack == "manifest" else h(meta.read_bytes())
    if attack == "none":
        assert recovery.validate_runtime(tmp_path, sha).executable_admission is False
        with pytest.raises(SystemExit, match="RECOVERY_POLICY_NOT_ACTIVATED"):
            exec(compile(body, "<quarantine-test>", "exec"), {})
    else:
        with pytest.raises(ValueError):
            recovery.validate_runtime(tmp_path, sha)
