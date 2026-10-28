"""Real built image, real CLI/receipts/preview; synthetic Namespace and private ledger.

No sudo, setns, capture, DNS, external API or production approval/ledger writes.
Only namespace observation and root-owned installation ownership are substituted.
"""

import json
import os
import shutil
import time
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_isolated_dns_launcher import lease
from tests.unit.ebpf_tc.test_namespace_runtime import NS, config
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import activate_fixture, h
from tests.unit.ebpf_tc.test_r1r2_operational import review as review_fixture
from tests.unit.ebpf_tc.test_runtime_recovery import package as package
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import (
    installation,
    isolated_dns_launcher,
    namespace_controller,
    operational_recovery,
    phase_d,
    r2_diagnostic,
    unified_image,
)
from soc_agent.security_ai.ebpf_tc.execution_management import (
    ManagementApproval,
    implementation_sha,
)
from soc_agent.security_ai.ebpf_tc.execution_request import ExecutionRequest
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.namespace_runtime import NamespaceBuild
from soc_agent.security_ai.ebpf_tc.r2_diagnostic import TrafficReceipt, scenario_for_namespace
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
from soc_agent.security_ai.ebpf_tc.release import _open_file
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding
from soc_agent.security_ai.native_campaign import NativeCampaign


@pytest.fixture(scope="module")
def built(tmp_path_factory, package):
    root = tmp_path_factory.mktemp("controller-real-cli")
    source, release = package
    installed = root / "installed"
    shutil.copytree(source, installed)
    for name, payload in release.payloads.items():
        (installed / name).chmod(payload.mode)
    for name in ("release.json", "release.trust"):
        (installed / name).chmod(0o444)
    origin = RootBinding(
        session="00000000-0000-4000-8000-000000000001",
        artifact=Artifact(
            git_commit="1" * 40,
            git_tree="2" * 40,
            release=release.version,
            manifest="a" * 64,
            bundle="b" * 64,
            image="c" * 64,
            root_manifest=release.identity,
        ),
        source_snapshot="d" * 64,
        scope_sha="e" * 64,
        installed_manifest=release.identity,
        rollback_manifest=release.identity,
    )
    patch = pytest.MonkeyPatch()
    patch.setattr(isolated_dns_launcher, "inspect_lease", lambda *_: lease(origin))
    patch.setattr(unified_image, "INSTALL", installed)
    patch.setattr(installation, "INSTALL", installed)
    installation_held = installation.read_held
    patch.setattr(
        installation,
        "read_held",
        lambda p, **kw: installation_held(
            p, **(kw | dict(owner=os.getuid()) if p.is_relative_to(installed) else kw)
        ),
    )
    patch.setattr(installation, "_open_file", lambda *a: _open_file(*a, owner=os.getuid()))
    held = unified_image.read_held
    patch.setattr(
        unified_image,
        "read_held",
        lambda p, **kw: held(
            p, **(kw | dict(owner=os.getuid()) if p.is_relative_to(installed) else kw)
        ),
    )
    try:
        build = NamespaceBuild(
            lease_file=root / "synthetic-lease", lease_sha="a" * 64, origin=origin
        )
        pending = phase_d.prepare(root / "guarded", namespace_build=build)
        policy = dict(
            contract="SOC_NAMESPACE_SUPERVISOR_BUILD_POLICY_V1",
            decision="APPROVED",
            approver="SYNTHETIC_TEST_OWNER_NOT_REAL_APPROVAL",
            human_reference_sha="b" * 64,
            binding=pending["build_review"]["policy_input"],
            issued_at=int(time.time()) - 1,
            expires_at=int(time.time()) + 3600,
            activate_namespace_supervisor=True,
            authorize_root=False,
            authorize_native=False,
            authorize_traffic=False,
        )
        path = root / "synthetic-build-policy.json"
        path.write_bytes(canonical(policy))
        image = phase_d.prepare(
            root / "candidate",
            namespace_build=build.model_copy(
                update=dict(policy_file=path, policy_sha=h(path.read_bytes()))
            ),
        )
        yield root / "candidate", image, h(path.read_bytes())
    finally:
        patch.undo()


@pytest.fixture
def admission(stable, built, tmp_path, monkeypatch):
    directory, image, policy_sha = built
    campaign, execution, scope, dns = stable
    scope["namespace"] = dns["namespace"] = NS
    budget_path = campaign / "budget.json"
    budget = json.loads(budget_path.read_bytes())
    budget["scope"]["namespace"] = NS
    budget_path.write_bytes(canonical(budget))
    genesis_path = campaign / "execution-ledger.jsonl"
    genesis = json.loads(genesis_path.read_bytes())
    genesis["budget_sha256"] = h(budget_path.read_bytes())
    genesis_path.write_bytes(canonical(genesis))
    review = review_fixture.__wrapped__(stable)
    git, tree = operational_recovery.source_git_identity()
    artifact = Artifact(
        git_commit=git,
        git_tree=tree,
        release="0.6.3",
        manifest=image["manifest"],
        bundle=image["bundle"],
        image=image["image"],
        root_manifest=image["tcx_manifest"],
    )
    binding = review["expected_binding"].model_copy(update=dict(next_artifact=artifact))
    review["expected_binding"] = binding
    path = review["procedure_file"]
    path.write_bytes(
        canonical(json.loads(path.read_bytes()) | dict(binding_sha=digest(binding.model_dump())))
    )
    review["procedure_sha"] = h(path.read_bytes())
    path = review["receipt_file"]
    path.write_bytes(
        canonical(
            json.loads(path.read_bytes())
            | dict(binding=binding.model_dump(), procedure_sha=review["procedure_sha"])
        )
    )
    review["receipt_sha"] = h(path.read_bytes())
    ledger, execution, scope, dns = activate_fixture(review, stable)
    claim, traffic = tmp_path / "unclaimed", tmp_path / "traffic.json"
    traffic.write_bytes(
        canonical(
            TrafficReceipt(
                decision="APPROVED",
                approver="SYNTHETIC_NOT_HUMAN",
                human_reference_sha="f" * 64,
                session=binding.next_session,
                artifact=artifact,
                claim_path=str(claim),
                scenario=scenario_for_namespace(NS, policy_sha),
                implementation_sha=h(Path(r2_diagnostic.__file__).read_bytes()),
                issued_at=int(time.time()) - 1,
                expires_at=int(time.time()) + 600,
            ).model_dump()
        )
    )
    identity = dict(
        manifest=artifact.manifest,
        bundle=artifact.bundle,
        image=artifact.image,
        tcx_manifest=artifact.root_manifest,
    )
    execution.write_bytes(
        canonical(
            json.loads(execution.read_bytes())
            | dict(
                release=identity, scope=scope, dns_scope=dns, r2_receipt_sha=h(traffic.read_bytes())
            )
        )
    )
    management = tmp_path / "management.json"
    management.write_bytes(
        canonical(
            ManagementApproval(
                decision="APPROVED",
                approver="SYNTHETIC_NOT_HUMAN",
                human_reference_sha="a" * 64,
                binding=binding,
                implementation_sha=implementation_sha(),
                budget_sha=h(ledger.budget_body),
                baseline_sha=h(ledger.baseline_body),
                issued_at=int(time.time()) - 1,
                expires_at=int(time.time()) + 600,
                activate_delayed_reservation=True,
            ).model_dump()
        )
    )
    data = config(tmp_path)
    data["target"] = dict(
        directory=str(directory),
        manifest=artifact.manifest,
        image_sha=artifact.image,
        campaign=str(campaign),
    )
    request = ExecutionRequest(
        **data["target"],
        amendment_file=str(campaign / "FIXTURE_amendment.json"),
        amendment_sha=ledger.amendment_sha,
        approval_file=str(execution),
        approval_sha=h(execution.read_bytes()),
        traffic_file=str(traffic),
        traffic_sha=h(traffic.read_bytes()),
        claim_file=str(claim),
        management_file=str(management),
        management_sha=h(management.read_bytes()),
    )
    Path(data["request_file"]).write_bytes(canonical(request.model_dump()))
    original = os.readlink
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path, *a, **kw: NS if str(path) == "/proc/self/ns/net" else original(path, *a, **kw),
    )
    return data, request, ledger, genesis_path, claim


@pytest.mark.parametrize(
    "fault", [None, "stale", "session", "release", "sha", "namespace", "duplicate", "replay"]
)
def test_actual_controller_check_uses_built_image_and_real_admission(admission, monkeypatch, fault):
    data, request, ledger, path, claim = admission
    if fault == "stale":
        NativeCampaign._locked(ledger, lambda _rows: dict(event="SYNTHETIC_UNRELATED_APPEND"))
    elif fault in {"session", "release"}:
        receipt = Path(request.traffic_file)
        data_receipt = json.loads(receipt.read_bytes())
        if fault == "session":
            data_receipt["session"] = "WRONG_SESSION"
        else:
            data_receipt["artifact"]["release"] = "WRONG_RELEASE"
        receipt.write_bytes(canonical(data_receipt))
        request = request.model_copy(update=dict(traffic_sha=h(receipt.read_bytes())))
    elif fault == "sha":
        request = request.model_copy(update=dict(approval_sha="0" * 64))
    elif fault == "replay":
        claim.write_text("SYNTHETIC_CONSUMED_TRAFFIC_CLAIM")
    elif fault == "namespace":
        monkeypatch.setattr(os, "readlink", lambda *_: "net:[4026531833]")
    Path(data["request_file"]).write_bytes(canonical(request.model_dump()))
    before = path.read_bytes()
    state, results = {}, []
    if fault in (None, "duplicate"):
        args = namespace_controller.check_request(
            data, h(Path(data["request_file"]).read_bytes()), state, results.append
        )
        assert args[0] == data["target"]["directory"]
        assert results[-1]["status"] == "EXECUTION_READY"
        assert results[-1]["admission_context"]["session"] == ledger.amendment.binding.next_session
        if fault == "duplicate":
            namespace_controller.check_request(
                data, h(Path(data["request_file"]).read_bytes()), {}, results.append
            )
            assert results[-1]["status"] == "EXECUTION_READY"
            # Read-only preview is repeatable and never consumes an approval.
    else:
        with pytest.raises(SystemExit) as stopped:
            namespace_controller.check_request(
                data, h(Path(data["request_file"]).read_bytes()), state, results.append
            )
        assert stopped.value.code == 2 and results[-1]["status"] == "BLOCKED"
        assert results[-1]["failure_origin"]
    (Path(data["source_pins"]).parent / "admission-preview-result.json").write_bytes(
        canonical(
            dict(
                evidence_class="SYNTHETIC_NAMESPACE_REAL_BUILT_IMAGE_REAL_CLI",
                fault=fault,
                result=results[-1],
                ledger_before=h(before),
                ledger_after=h(path.read_bytes()),
                native_executed=False,
            )
        )
    )
    assert path.read_bytes() == before
    assert claim.exists() is (fault == "replay")
    assert not (Path(data["target"]["directory"]) / "execution-management").exists()
