"""Actual CLI/image pipeline plus temporary approval ledgers; no Root or traffic."""

import json
import os
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import activate_fixture, h, step
from tests.unit.ebpf_tc.test_r1r2_operational import launcher as launcher
from tests.unit.ebpf_tc.test_r1r2_operational import review as review
from tests.unit.ebpf_tc.test_runtime_recovery import abi_report
from tests.unit.ebpf_tc.test_runtime_recovery import package as package
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent import cli
from soc_agent.security_ai.ebpf_tc import operational_recovery as operational
from soc_agent.security_ai.ebpf_tc import phase_d, runtime_recovery, unified_image
from soc_agent.security_ai.ebpf_tc import r2_diagnostic as r2
from soc_agent.security_ai.ebpf_tc.install_image import installation_payload, payload_from_release
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.recovery_policy import (
    RecoveryApproval,
    RecoveryBuild,
    check_policy,
    image_constants,
    validate_image_recovery,
)
from soc_agent.security_ai.ebpf_tc.release import _open_file
from soc_agent.security_ai.ebpf_tc.supervisor import SupervisorImage
from soc_agent.security_ai.ebpf_tc.unified_image_engine import _recovery_policy


@pytest.fixture(scope="module")
def prepared(tmp_path_factory, package):
    root = tmp_path_factory.mktemp("operational-recovery")
    source, previous = package
    installed = root / "installed"
    shutil.copytree(source, installed)
    for name, payload in previous.payloads.items():
        (installed / name).chmod(payload.mode)
    for name in ("release.json", "release.trust"):
        (installed / name).chmod(0o444)
    patch = pytest.MonkeyPatch()
    patch.setattr(runtime_recovery, "INSTALL", installed)
    patch.setattr(runtime_recovery, "_directory", lambda *_: None)
    patch.setattr(runtime_recovery, "_open_file", lambda *a: _open_file(*a, owner=os.getuid()))
    patch.setattr(unified_image, "INSTALL", installed)
    original = unified_image.read_held
    patch.setattr(
        unified_image,
        "read_held",
        lambda p, **kw: original(
            p, **(kw | {"owner": os.getuid()} if p.is_relative_to(installed) else kw)
        ),
    )
    data = abi_report(previous)
    data["libraries"]["old"]["sha256"] = data["libraries"]["new"]["sha256"]
    abi = root / "fixture-abi.json"
    abi.write_bytes(canonical(data))
    request = RecoveryBuild(
        installed_manifest=previous.identity, abi_file=abi, abi_sha=h(abi.read_bytes())
    )
    try:
        pending_dir = root / "pending"
        pending = phase_d.prepare(pending_dir, recovery=request)
        descriptor = SupervisorImage.model_validate_json(
            (pending_dir / "supervisor-image.json").read_bytes()
        )
        policy = RecoveryApproval(
            decision="APPROVED",
            approver="SYNTHETIC_POLICY_OWNER_NOT_REAL_APPROVAL",
            human_reference_sha="7" * 64,
            binding=descriptor.recovery_binding,
            issued_at=int(time.time()) - 5,
            expires_at=int(time.time()) + 3600,
            activate_retention_replacement=True,
            authorize_root=False,
            authorize_native=False,
        )
        policy_file = root / "fixture-policy.json"
        policy_file.write_bytes(canonical(policy.model_dump()))
        approved_dir = root / "fixture-approved"
        approved = phase_d.prepare(
            approved_dir,
            recovery=request.model_copy(
                update=dict(policy_file=policy_file, policy_sha=h(policy_file.read_bytes()))
            ),
        )
        yield root, previous, pending, approved, policy
    finally:
        patch.undo()


def test_actual_cli_check_and_execute_pending_never_authenticate(prepared, monkeypatch, capsys):
    root, _, pending, _, _ = prepared
    from soc_agent.security_ai.ebpf_tc import reassessment_admission
    from soc_agent.security_ai.ebpf_tc.supervisor import SupervisedSession

    monkeypatch.setattr(
        SupervisedSession, "authenticate_native", lambda *_: pytest.fail("Root auth")
    )
    monkeypatch.setattr(reassessment_admission, "execute", lambda *a, **kw: pytest.fail("Native"))
    monkeypatch.setattr(r2, "_udp_witness", lambda: pytest.fail("traffic"))
    for mode in ("check", "execute"):
        assert (
            cli.main(
                [
                    "native-recovery",
                    mode,
                    str(root / "pending"),
                    "--manifest",
                    pending["manifest"],
                    "--image-sha",
                    pending["image"],
                ]
            )
            == 2
        )
        result = json.loads(capsys.readouterr().out)
        assert result["error"] == "RECOVERY_POLICY_APPROVAL_REQUIRED"
        assert result["stages"]["RUNTIME_VERIFIED"] == "VERIFIED"
        assert not result["reserved"] and not result["executed"]


def test_real_supervisor_binding_and_root_policy_missing(prepared):
    root, previous, pending, _, _ = prepared
    directory = root / "pending"
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    release, payload = installation_payload(directory / "release", pending["tcx_manifest"])
    assert (
        validate_image_recovery(image, release, require_policy=False)["status"]
        == "POLICY_APPROVAL_REQUIRED"
    )
    engine = image_constants(image.path)
    with pytest.raises(ValueError, match="POLICY_APPROVAL_REQUIRED"):
        _recovery_policy(payload, payload_from_release(root / "installed", previous), engine)
    assert engine["RECOVERY_POLICY_BODY"] is None


def test_fixture_approved_image_reuses_supervisor_and_has_independent_r1_gate(prepared):
    root, previous, _, approved, _ = prepared
    directory = root / "fixture-approved"
    image = SupervisorImage.model_validate_json((directory / "supervisor-image.json").read_bytes())
    release, payload = installation_payload(directory / "release", approved["tcx_manifest"])
    assert (
        validate_image_recovery(image, release, require_policy=True)["status"] == "RUNTIME_APPROVED"
    )
    _recovery_policy(
        payload, payload_from_release(root / "installed", previous), image_constants(image.path)
    )
    result = operational.readiness(directory, approved["manifest"], approved["image"])
    assert result["error"] == "R1_AMENDMENT_REQUIRED"
    assert result["stages"]["POLICY_APPROVED"] == "VERIFIED"
    assert not result["executed"]


@pytest.mark.parametrize(
    "change",
    [
        dict(decision="PENDING"),
        dict(approver=""),
        dict(issued_at=2**40),
        dict(expires_at=1),
        dict(authorize_root=True),
        dict(human_reference_sha="invalid"),
    ],
)
def test_policy_fail_closed(prepared, change):
    *_, policy = prepared
    with pytest.raises((ValueError, ValidationError)):
        check_policy(policy.model_dump() | change, policy.binding)


def test_source_or_image_tamper_cannot_reach_execution(prepared, tmp_path, monkeypatch):
    root, _, pending, _, _ = prepared
    directory = tmp_path / "tampered"
    shutil.copytree(root / "pending", directory)
    path = directory / "supervisor-image.py"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"\n# tampered\n")
    path.chmod(0o400)
    meta = directory / "supervisor-image.json"
    meta.write_bytes(canonical(json.loads(meta.read_bytes()) | dict(path=str(path))))
    result = operational.readiness(directory, pending["manifest"], pending["image"])
    assert result["status"] == "BLOCKED" and not result["executed"]
    assert result["stages"]["SOURCE_VERIFIED"] == "BLOCKED"


def mock_entry_context(review, stable, tmp_path, monkeypatch):
    # Real R1 review/admission validators + temporary chain; only artifact/OS
    # observation is synthetic. This test never calls the execution dispatcher.
    binding = review["expected_binding"]
    a = binding.next_artifact.model_copy(update=dict(root_manifest="e" * 64))
    binding = binding.model_copy(update=dict(next_artifact=a))
    review["expected_binding"] = binding
    p = review["procedure_file"]
    p.write_bytes(
        canonical(
            json.loads(p.read_bytes()) | dict(binding_sha=operational_digest(binding.model_dump()))
        )
    )
    review["procedure_sha"] = h(p.read_bytes())
    p = review["receipt_file"]
    p.write_bytes(
        canonical(
            json.loads(p.read_bytes())
            | dict(binding=binding.model_dump(), procedure_sha=review["procedure_sha"])
        )
    )
    review["receipt_sha"] = h(p.read_bytes())
    ledger, execution, scope, dns = activate_fixture(review, stable)
    identity = dict(
        manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
    )
    traffic = tmp_path / "fixture-traffic.json"
    claim = tmp_path / "never-created-claim"
    receipt = r2.TrafficReceipt(
        decision="APPROVED",
        approver="FIXTURE_HUMAN",
        human_reference_sha="6" * 64,
        session=binding.next_session,
        claim_path=str(claim.absolute()),
        artifact=a,
        scenario=r2.Scenario(),
        implementation_sha=h(Path(r2.__file__).read_bytes()),
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 100,
    )
    traffic.write_bytes(canonical(receipt.model_dump()))
    execution.write_bytes(
        canonical(
            json.loads(execution.read_bytes())
            | dict(release=identity, r2_receipt_sha=h(traffic.read_bytes()))
        )
    )
    image = SupervisorImage(
        path=tmp_path / "not-executed.py",
        sha256=a.image,
        manifest=a.root_manifest,
        previous_manifest=binding.previous_artifact.root_manifest,
        version="0.6.3",
        action="UPDATE_RETAIN_PREVIOUS",
        zeek_bundle="1" * 64,
        scope_namespace="net:[4026531833]",
        dns_sidecar=True,
    )
    (tmp_path / "supervisor-image.json").write_text(image.model_dump_json())
    (tmp_path / "dns-sidecar").mkdir()
    (tmp_path / "dns-sidecar/release.json").write_bytes(canonical(dict(scope=dns)))
    value = dict(bundle=a.bundle, tcx_manifest=a.root_manifest, scope=scope)
    monkeypatch.setattr(phase_d, "validate", lambda *args: value)
    monkeypatch.setattr(operational, "source_git_identity", lambda: (a.git_commit, a.git_tree))
    monkeypatch.setattr(
        unified_image,
        "installed_release",
        lambda: SimpleNamespace(identity=image.previous_manifest),
    )
    return ledger, dict(
        directory=tmp_path,
        manifest=a.manifest,
        image=a.image,
        campaign=ledger.directory,
        amendment_file=ledger.directory / "FIXTURE_amendment.json",
        amendment_sha=ledger.amendment_sha,
        approval_file=execution,
        approval_sha=h(execution.read_bytes()),
        traffic_file=traffic,
        traffic_sha=h(traffic.read_bytes()),
        claim_file=claim,
    )


def operational_digest(value):
    from soc_agent.security_ai.ebpf_tc.reassessment import digest

    return digest(value)


@pytest.mark.parametrize("missing", [None, "traffic_file", "approval_file", "amendment_file"])
def test_complete_mock_approval_readiness_is_nonconsuming(
    review, stable, tmp_path, monkeypatch, missing
):
    ledger, kwargs = mock_entry_context(review, stable, tmp_path, monkeypatch)
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    if missing:
        kwargs[missing] = None
    result = operational.readiness(**kwargs)
    assert result["status"] == ("BLOCKED" if missing else "EXECUTION_READY")
    assert not result["executed"] and not result["reserved"]
    assert not kwargs["claim_file"].exists()
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("installed_state", ["matching", "changed", "missing", "damaged"])
def test_failed_release_is_independent_of_current_installation(
    review, stable, tmp_path, monkeypatch, installed_state
):
    ledger, kwargs = mock_entry_context(review, stable, tmp_path, monkeypatch)
    path = tmp_path / "supervisor-image.json"
    descriptor = SupervisorImage.model_validate_json(path.read_bytes())
    current_manifest = "c" * 64
    assert current_manifest != ledger.amendment.binding.previous_artifact.root_manifest
    path.write_text(
        descriptor.model_copy(update=dict(previous_manifest=current_manifest)).model_dump_json()
    )

    def installed():
        if installed_state == "damaged":
            raise ValueError("ROOT_RELEASE_MANIFEST_MISMATCH")
        if installed_state == "missing":
            return None
        return SimpleNamespace(
            identity=current_manifest if installed_state == "matching" else "d" * 64
        )

    monkeypatch.setattr(unified_image, "installed_release", installed)
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    result = operational.readiness(**kwargs)
    assert result["status"] == ("EXECUTION_READY" if installed_state == "matching" else "BLOCKED")
    assert not result["reserved"] and not result["executed"]
    assert not kwargs["claim_file"].exists()
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize("attack", ["root", "native", "sha", "git", "session", "replay"])
def test_cli_readiness_invalid_grants_preserve_ledger(
    review, stable, tmp_path, monkeypatch, attack
):
    ledger, kwargs = mock_entry_context(review, stable, tmp_path, monkeypatch)
    path = kwargs["approval_file"]
    data = json.loads(path.read_bytes())
    if attack == "root":
        data["root_installations"] = 0
    elif attack == "native":
        data["native_attempts"] = 0
    elif attack == "session":
        data["next_session"] = "other-session"
    elif attack == "git":
        monkeypatch.setattr(operational, "source_git_identity", lambda: ("0" * 40, "0" * 40))
    elif attack == "replay":
        ledger.reserve(
            kwargs["identity"] if "identity" in kwargs else data["release"],
            data["scope"],
            data["dns_scope"],
            path,
            h(path.read_bytes()),
            root_cost=1,
        )
    path.write_bytes(canonical(data))
    kwargs["approval_sha"] = "0" * 64 if attack == "sha" else h(path.read_bytes())
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    result = operational.readiness(**kwargs)
    assert result["status"] == "BLOCKED" and not result["executed"]
    assert not kwargs["claim_file"].exists()
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_retained_file_failure_does_not_make_current_runtime_invalid(prepared):
    root, _, pending, _, _ = prepared
    target = root / "installed/broker"
    original = target.stat().st_mode & 0o777
    target.chmod(0o777)
    try:
        result = operational.readiness(root / "pending", pending["manifest"], pending["image"])
        assert result["status"] == "BLOCKED"
        # Independent current-runtime package still validates, old file integrity does not.
        from soc_agent.security_ai.ebpf_tc.installation import verify_package

        assert (
            verify_package(root / "pending/release", pending["tcx_manifest"]).identity
            == pending["tcx_manifest"]
        )
    finally:
        target.chmod(original)


@pytest.mark.parametrize(
    "result,code",
    [
        (dict(cleanup_status="PROCESS_AND_AUDIT_VERIFIED", last_error=None), 0),
        (dict(cleanup_status="CLEANUP_UNVERIFIED", last_error=None), 1),
        (dict(cleanup_status="PROCESS_AND_AUDIT_VERIFIED", last_error="FAILED"), 1),
    ],
)
def test_cli_execution_exit_preserves_failure(monkeypatch, capsys, result, code):
    from soc_agent.security_ai.ebpf_tc import reassessment_admission

    monkeypatch.setattr(operational, "readiness", lambda *a, **kw: dict(status="EXECUTION_READY"))
    monkeypatch.setattr(reassessment_admission, "execute", lambda *a, **kw: result)
    assert (
        cli.main(
            [
                "native-recovery",
                "execute",
                "/fixture-not-a-real-run",
                "--manifest",
                "a" * 64,
                "--image-sha",
                "b" * 64,
            ]
        )
        == code
    )
    assert json.loads(capsys.readouterr().out) == result


def test_r2_missing_close_or_late_witness_stays_incomplete(launcher):
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    assert not step(launch, 40, tcp_closed_ns=None)
    assert launch.witness is None
    assert step(launch, 60, tcp_closed_ns=None)
    assert launch.stop_reason.startswith("INCOMPLETE")


def test_r2_witness_clock_cannot_be_fabricated(launcher, monkeypatch):
    monkeypatch.setattr(
        r2, "_udp_witness", lambda: dict(sent_monotonic_ns=1, received_monotonic_ns=0)
    )
    launch = r2.R2Launcher(launcher)
    launch.start(0)
    with pytest.raises(ValueError, match="WITNESS_CLOCK"):
        step(launch, 37)
    assert launch.attempted  # Failed traffic is never automatically retried.
    assert launch.snapshot()["eligibility"] == "NOT_ASSESSED_BY_LAUNCHER"


def test_actual_reassess_cli_requires_pinned_human_grants_and_keeps_false(review, tmp_path, capsys):
    ledger = review["campaign"]
    path = ledger.directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    packet = tmp_path / "fixture-evidence-packet.json"
    packet.write_bytes(
        canonical(
            dict(
                evidence=review["evidence"].model_dump(),
                binding=review["expected_binding"].model_dump(),
                source_paths={k: str(v) for k, v in review["source_paths"].items()},
            )
        )
    )
    argv = [
        "native-recovery",
        "reassess",
        str(tmp_path),
        "--campaign",
        str(ledger.directory),
        "--procedure-file",
        str(review["procedure_file"]),
        "--procedure-sha",
        review["procedure_sha"],
        "--review-file",
        str(review["receipt_file"]),
        "--review-sha",
        review["receipt_sha"],
        "--evidence-file",
        str(packet),
        "--evidence-sha",
        h(packet.read_bytes()),
    ]
    assert cli.main(argv) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["event"] == "SAFETY_REASSESSMENT_RECORDED_V1"
    assert not result["authorizes_execution"]
    assert path.read_bytes().startswith(before)
    assert b'"safe_for_next_attempt":false' in before
    after = path.read_bytes()
    assert cli.main(argv) == 2  # stale tip/replay must not append again
    capsys.readouterr()
    assert path.read_bytes() == after
