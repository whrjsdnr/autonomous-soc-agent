"""Real built bytes/CLI and temporary approvals only. No live permissions or traffic."""

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.unit.ebpf_tc.test_controller_admission_path import admission as admission
from tests.unit.ebpf_tc.test_controller_admission_path import built as built
from tests.unit.ebpf_tc.test_controller_admission_path import fixture as fixture
from tests.unit.ebpf_tc.test_controller_admission_path import package as package
from tests.unit.ebpf_tc.test_controller_admission_path import stable as stable
from tests.unit.ebpf_tc.test_development_session import policy_case as policy_case
from tests.unit.ebpf_tc.test_isolated_dns_launcher import lease

from soc_agent.security_ai.ebpf_tc import development_integrity as integrity
from soc_agent.security_ai.ebpf_tc import development_session as dev
from soc_agent.security_ai.ebpf_tc import namespace_controller as controller
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding
from soc_agent.security_ai.ebpf_tc.source_guard import snapshot


@pytest.fixture
def automatic_case(admission, tmp_path):
    config, request, campaign, path, claim = admission
    first = Path(config["target"]["directory"])
    second = tmp_path / "second-build"
    shutil.copytree(first, second)
    project, export = tmp_path / "project", tmp_path / "source-export"
    (project / "src").mkdir(parents=True)
    (project / "src/app.py").write_text("value = 1\n")
    shutil.copytree(project, export)
    artifact = Artifact.model_validate(
        json.loads(Path(request.amendment_file).read_bytes())["binding"]["next_artifact"]
    )
    automation = integrity.ArtifactAutomation(
        request_file=Path(config["request_file"]),
        project=project,
        source_export=export,
        first_build=first,
        second_build=second,
        source_pins=snapshot(project),
        allowed_source_changes=["src/app.py"],
        reference_artifact=artifact,
        boundary_sha=digest(integrity.boundary(first)),
    )
    policy = SimpleNamespace(
        artifact_automation=automation,
        artifacts=[artifact],
        namespace="net:[4999999999]",
        lease_file=Path("/synthetic-lease"),
        lease_sha="a" * 64,
        namespace_origin=RootBinding(
            session="00000000-0000-4000-8000-000000000001",
            artifact=artifact,
            source_snapshot="d" * 64,
            scope_sha="e" * 64,
            installed_manifest=artifact.root_manifest,
            rollback_manifest=artifact.root_manifest,
        ).model_dump(mode="json"),
    )
    rows = [json.loads(x) for x in path.read_bytes().splitlines()]
    return config, request, campaign, path, claim, policy, rows


@pytest.mark.parametrize("fault", [None, "source", "unlisted", "build", "root", "scope", "sha"])
def test_actual_byte_verification_and_changes(automatic_case, fault):
    config, request, _, ledger, _, policy, rows = automatic_case
    auto = policy.artifact_automation
    before = ledger.read_bytes()
    if fault == "source":
        (auto.project / "src/app.py").write_text("value = 2\n")
        (auto.source_export / "src/app.py").write_text("value = 2\n")
    elif fault == "unlisted":
        (auto.project / "src/extra.py").write_text("value = 2\n")
    elif fault == "build":
        (auto.second_build / "extra").write_text("changed")
    elif fault == "root":
        policy.artifact_automation = auto.model_copy(
            update=dict(
                reference_artifact=auto.reference_artifact.model_copy(
                    update=dict(root_manifest="0" * 64)
                )
            )
        )
        policy.artifacts = [policy.artifact_automation.reference_artifact]
    elif fault == "scope":
        policy.artifact_automation = auto.model_copy(update=dict(boundary_sha="0" * 64))
    elif fault == "sha":
        Path(config["request_file"]).write_bytes(
            canonical(request.model_copy(update=dict(manifest="0" * 64)).model_dump())
        )
    if fault in (None, "source"):
        assert integrity.verified_artifact(policy, rows) == auto.reference_artifact
    else:
        with pytest.raises(ValueError, match="AUTOMATION_"):
            integrity.verified_artifact(policy, rows)
    assert ledger.read_bytes() == before


def test_source_change_outside_approved_list_requires_review(automatic_case):
    *_, policy, rows = automatic_case
    auto = policy.artifact_automation
    policy.artifact_automation = auto.model_copy(update=dict(allowed_source_changes=[]))
    for root in (auto.project, auto.source_export):
        (root / "src/app.py").write_text("changed")
    with pytest.raises(ValueError, match="SOURCE_CHANGE_REQUIRES_REVIEW"):
        integrity.verified_artifact(policy, rows)


def test_missing_activation_cannot_automatically_select_request(automatic_case):
    config, _, _, ledger, _, _, _ = automatic_case
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="POLICY_NOT_ACTIVATED"):
        integrity.automatic_request_pin(config | dict(automatic_request_policy_sha="a" * 64))
    assert ledger.read_bytes() == before


def test_controller_auto_pin_still_runs_real_cli_and_exact_receipts(admission, monkeypatch):
    config, request, _, ledger, claim = admission
    # UI/policy-selection boundary substituted here; byte/policy tests above are
    # independent. Real operational check, receipts, Replay and Native preview.
    pin = digest(request.model_dump())
    monkeypatch.setattr(integrity, "automatic_request_pin", lambda _: pin)
    monkeypatch.setattr(integrity, "approved_source_pins", lambda _, original: original)
    config["automatic_request_policy_sha"] = "a" * 64
    before = ledger.read_bytes()
    results = []
    controller.check_request(config, pin, {}, results.append)
    assert results[-1]["status"] == "EXECUTION_READY"
    claim.write_text("SYNTHETIC_CONSUMED_CLAIM")
    with pytest.raises((ValueError, SystemExit)):
        controller.check_request(config, pin, {}, results.append)
    assert ledger.read_bytes() == before


def test_existing_development_policy_has_no_implicit_automation(policy_case):
    campaign, policy, packet = policy_case
    assert policy.artifact_automation is None
    before = (campaign.directory / "execution-ledger.jsonl").read_bytes()
    dev.activate(campaign, packet)
    with pytest.raises(ValueError, match="REPLAY"):
        dev.activate(campaign, packet)
    after = (campaign.directory / "execution-ledger.jsonl").read_bytes()
    assert after.startswith(before) and len(after.splitlines()) == len(before.splitlines()) + 1


def test_activated_policy_computes_sha_without_user_input(automatic_case, policy_case, monkeypatch):
    config, request, _, _, _, checked_policy, _ = automatic_case
    campaign, policy, packet = policy_case
    policy = policy.model_copy(
        update=dict(
            namespace=checked_policy.namespace,
            artifacts=checked_policy.artifacts,
            artifact_automation=checked_policy.artifact_automation,
            lease_file=checked_policy.lease_file,
            lease_sha=checked_policy.lease_sha,
            namespace_origin=checked_policy.namespace_origin,
        )
    )
    from soc_agent.security_ai.ebpf_tc import isolated_dns_launcher

    monkeypatch.setattr(
        isolated_dns_launcher,
        "inspect_lease",
        lambda *_: lease(RootBinding.model_validate(policy.namespace_origin)),
    )
    policy_file = Path(packet["policy_file"])
    policy_file.write_bytes(canonical(policy.model_dump(mode="json")))
    packet["policy_sha"] = digest(policy.model_dump(mode="json"))
    dev.activate(campaign, packet)
    config["target"]["campaign"] = str(campaign.directory)
    config["project"] = str(policy.artifact_automation.project)
    config["automatic_request_policy_sha"] = packet["policy_sha"]
    before = (campaign.directory / "execution-ledger.jsonl").read_bytes()
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("No SHA prompt"))
    assert integrity.automatic_request_pin(config) == digest(request.model_dump())
    assert (campaign.directory / "execution-ledger.jsonl").read_bytes() == before


def test_security_implementation_change_cannot_be_automatically_approved(policy_case):
    campaign, policy, _ = policy_case
    with pytest.raises(ValueError, match="BINDING_OR_EXPIRY"):
        dev._validate(
            policy.model_copy(update=dict(security_implementation_sha="0" * 64)), campaign.budget
        )


@pytest.mark.parametrize("change", ["capabilities", "scope", "tcx_manifest", "dns_manifest"])
def test_boundary_includes_privilege_root_collector_and_dns(automatic_case, change):
    *_, policy, _ = automatic_case
    config = policy.artifact_automation
    phase = config.first_build / "phase-d.json"
    data = json.loads(phase.read_bytes())
    original = digest(integrity.boundary(config.first_build))
    # Work on the per-test independent copy; never mutate the shared built fixture.
    phase = config.second_build / "phase-d.json"
    data[change] = "UNAPPROVED_CHANGE"
    phase.write_bytes(canonical(data))
    assert digest(integrity.boundary(config.second_build)) != original


def test_identical_self_hashed_candidates_do_not_prove_builder_provenance(automatic_case):
    config, request, _, ledger, _, policy, rows = automatic_case
    auto = policy.artifact_automation
    artifact = auto.reference_artifact
    before = ledger.read_bytes()
    for directory in (auto.first_build, auto.second_build):
        descriptor_path = directory / "supervisor-image.json"
        descriptor = json.loads(descriptor_path.read_bytes())
        executable = directory / Path(descriptor["path"]).name
        executable.chmod(0o600)
        executable.write_bytes(executable.read_bytes() + b"\n# untrusted additional bytes\n")
        executable.chmod(0o400)
        descriptor["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        descriptor_path.write_bytes(canonical(descriptor))
        phase_path = directory / "phase-d.json"
        phase = json.loads(phase_path.read_bytes())
        phase["image"] = descriptor["sha256"]
        phase_path.write_bytes(canonical(phase))
    phase_pin = hashlib.sha256((auto.first_build / "phase-d.json").read_bytes()).hexdigest()
    amended = json.loads(Path(request.amendment_file).read_bytes())
    amended["binding"]["next_artifact"] = artifact.model_copy(
        update=dict(manifest=phase_pin, image=descriptor["sha256"])
    ).model_dump()
    Path(request.amendment_file).write_bytes(canonical(amended))
    Path(config["request_file"]).write_bytes(
        canonical(
            request.model_copy(
                update=dict(
                    amendment_sha=digest(amended),
                    manifest=phase_pin,
                    image_sha=descriptor["sha256"],
                )
            ).model_dump()
        )
    )
    # The real existing DNS manifest catches the inconsistent image first.
    with pytest.raises(ValueError, match="PHASE_D_COLLECTOR_SCOPE_MISMATCH"):
        integrity.verified_artifact(policy, rows)
    # Even if self-declared manifests were made mutually consistent, the new
    # independent trusted reconstruction rejects the forged executable bytes.
    with pytest.raises(ValueError, match="IMAGE_BUILD_PROVENANCE"):
        integrity.verify_generated_image(
            policy, Artifact.model_validate(amended["binding"]["next_artifact"])
        )
    assert ledger.read_bytes() == before
