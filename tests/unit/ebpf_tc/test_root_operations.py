"""Temporary ledgers and compile-only packages; never sudo, setns or traffic."""

import json
import time
from dataclasses import dataclass

import pytest
from tests.unit.ebpf_tc.test_native_campaign import IDENTITY
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_runtime_recovery import package as package
from tests.unit.ebpf_tc.test_stabilization_campaign import approved, finish_review
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_native.contracts import ApplicationPlan, Scope, local_controller
from soc_agent.security_ai.ebpf_tc import root_operations as root
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.namespace_isolation import setup_proposal
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
from soc_agent.security_ai.native_campaign import sha
from soc_agent.security_ai.operation_budget import COSTS, guard_reservation, totals
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign


@dataclass
class Setup:
    ledger: root.RootOperations
    binding: root.RootBinding
    policy_file: object
    approval_file: object
    manifest: object

    def issue(self, operation="ROOT_SETUP", **changes):
        rows = [
            json.loads(line)
            for line in (self.ledger.directory / "execution-ledger.jsonl").read_bytes().splitlines()
        ]
        policy = root.RootPolicy(
            decision="APPROVED",
            approver="FIXTURE_NOT_HUMAN",
            human_reference_sha="a" * 64,
            binding=self.binding,
            implementation_sha=root.implementation_sha(),
            budget_sha=sha(self.ledger.budget_body),
            baseline_sha=sha(self.ledger.baseline_body),
            issued_at=int(time.time()) - 1,
            expires_at=int(time.time()) + 60,
        )
        self.policy_file.write_bytes(canonical(policy.model_dump()))
        approval = (
            root.RootApproval(
                decision="APPROVED",
                approver="FIXTURE_NOT_HUMAN",
                human_reference_sha="b" * 64,
                policy_sha=sha(self.policy_file.read_bytes()),
                binding=self.binding,
                operation=operation,
                scope=setup_proposal(),
                ledger_tip_sha=rows[-1].get("record_sha256", digest(rows[-1])),
                issued_at=policy.issued_at,
                expires_at=policy.expires_at,
            ).model_dump()
            | changes
        )
        self.approval_file.write_bytes(canonical(approval))
        return dict(
            policy_file=self.policy_file,
            policy_sha=sha(self.policy_file.read_bytes()),
            approval_file=self.approval_file,
            approval_sha=sha(self.approval_file.read_bytes()),
            root_manifest_file=self.manifest,
        )


@pytest.fixture
def setup(stable, package, monkeypatch):
    directory, _, _, _ = stable
    ledger = root.RootOperations(directory, "BATCH3")
    path, release = package
    artifact = Artifact(
        git_commit="1" * 40,
        git_tree="2" * 40,
        release=release.version,
        manifest="3" * 64,
        bundle="4" * 64,
        image="5" * 64,
        root_manifest=release.identity,
    )
    plan = ApplicationPlan(
        controller=local_controller(),
        scope=Scope(
            ifindex=1,
            net_namespace="net:[4026531833]",
            hook="INGRESS",
            program_sha256="a" * 64,
            loader_sha256="b" * 64,
            bundle_digest="c" * 64,
        ),
        mode="PHASE_A_NATIVE_BLOCKED",
    )
    binding = root.setup_binding(
        plan,
        artifact,
        source_snapshot="6" * 64,
        installed_manifest=release.identity,
        rollback_manifest=release.identity,
    )
    # Retention is tested on real files in test_runtime_recovery.
    monkeypatch.setattr(root, "inspect_retained", lambda *a, **kw: None)
    return Setup(
        ledger,
        binding,
        directory / "policy.json",
        directory / "root-approval.json",
        path / "release.json",
    )


def body(setup):
    return (setup.ledger.directory / "execution-ledger.jsonl").read_bytes()


def reserve(setup, **changes):
    return setup.ledger.reserve_root(setup.binding, **setup.issue(**changes))


def test_root_only_check_is_nonconsuming_and_reservation_independent(setup):
    args = setup.issue()
    before = body(setup)
    checked = setup.ledger.check_root(setup.binding, **args)
    assert checked["status"] == "CHECKED_NOT_RESERVED" and body(setup) == before
    event = setup.ledger.reserve_root(setup.binding, **args)
    assert (event["native_used"], event["root_installations_used"]) == (0, 1)
    assert body(setup).startswith(before) and event["state"] == "RESERVED_NOT_STARTED"
    with pytest.raises(ValueError, match="REPLAY"):
        setup.ledger.reserve_root(setup.binding, **args)


@pytest.mark.parametrize("state", ["START_INTENT", "STARTED", "SUCCEEDED", "FAILED", "UNKNOWN"])
def test_start_boundary_prevents_false_cancellation(setup, state):
    event = reserve(setup)
    ledger, attempt = setup.ledger, event["attempt_id"]
    ledger.record_root(attempt, state="START_INTENT", evidence_sha="a" * 64)
    with pytest.raises(ValueError, match="TRANSITION"):
        ledger.record_root(attempt, state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64)
    if state == "START_INTENT":
        return
    ledger.record_root(attempt, state="STARTED", evidence_sha="b" * 64)
    if state == "STARTED":
        return
    ledger.record_root(attempt, state=state, evidence_sha="c" * 64)
    before = body(setup)
    with pytest.raises(ValueError, match="ALREADY_SETTLED"):
        ledger.record_root(attempt, state=state, evidence_sha="d" * 64)
    assert body(setup) == before


def test_cancel_retains_charge_and_receipt_cannot_replay(setup):
    args = setup.issue()
    event = setup.ledger.reserve_root(setup.binding, **args)
    setup.ledger.record_root(
        event["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64
    )
    assert totals([json.loads(line) for line in body(setup).splitlines()]) == (0, 1)
    with pytest.raises(ValueError, match="REPLAY"):
        setup.ledger.reserve_root(setup.binding, **args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("session", "10000000-0000-0000-0000-000000000001"),
        ("source_snapshot", "f" * 64),
        ("artifact", None),
    ],
)
def test_binding_changes_fail_without_append(setup, field, value):
    args = setup.issue()
    data = setup.binding.model_dump()
    if field == "artifact":
        data[field]["release"] = "9.9.9"
    else:
        data[field] = value
    before = body(setup)
    with pytest.raises(ValueError, match="BINDING"):
        setup.ledger.reserve_root(root.RootBinding.model_validate(data), **args)
    assert body(setup) == before


@pytest.mark.parametrize(
    "changes",
    [
        dict(ledger_tip_sha="f" * 64),
        dict(scope={}),
        dict(expires_at=1),
        dict(native_cost=1),
        dict(operation="NATIVE_DIAGNOSTIC"),
        dict(approver=""),
        dict(mock=True),
        dict(binding={}),
    ],
)
def test_reject_invalid_receipts_without_consuming(setup, changes):
    before = body(setup)
    with pytest.raises(ValueError):
        reserve(setup, **changes)
    assert body(setup) == before


def test_missing_policy_and_manifest_tampering_block(setup, tmp_path):
    args = setup.issue()
    args["policy_file"] = tmp_path / "missing"
    with pytest.raises((ValueError, OSError)):
        setup.ledger.reserve_root(setup.binding, **args)
    args = setup.issue()
    bad = tmp_path / "release.json"
    bad.write_bytes(b"{}")
    args["root_manifest_file"] = bad
    with pytest.raises(ValueError):
        setup.ledger.reserve_root(setup.binding, **args)


def test_pending_root_blocks_legacy_native_even_with_valid_legacy_approval(setup, stable):
    reserve(setup)
    before = body(setup)
    _, path, scope, dns = stable
    pin = approved(stable, batch="BATCH3")
    with pytest.raises(ValueError, match="ROOT_OPERATION_UNRESOLVED"):
        StabilizationCampaign(setup.ledger.directory, "BATCH3").reserve(
            IDENTITY, scope, dns, path, pin, root_cost=1
        )
    assert body(setup) == before


def test_root_charge_counts_against_future_integrated_reservation(setup, stable):
    for index in range(2):
        setup.binding = setup.binding.model_copy(
            update=dict(session=f"00000000-0000-0000-0000-{index:012d}")
        )
        e = reserve(setup)
        setup.ledger.record_root(
            e["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64
        )
    _, path, scope, dns = stable
    pin = approved(stable, batch="BATCH3")
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        StabilizationCampaign(setup.ledger.directory, "BATCH3").reserve(
            IDENTITY, scope, dns, path, pin, root_cost=1
        )
    before = body(setup)
    setup.binding = setup.binding.model_copy(
        update=dict(session="00000000-0000-0000-0000-000000000002")
    )
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        reserve(setup)
    assert body(setup) == before


def test_native_only_preserves_root_and_integrated_counts_both(stable):
    directory, path, scope, dns = stable
    ledger = StabilizationCampaign(directory, "BATCH3")
    approved(stable, batch="BATCH3")
    receipt = json.loads(path.read_bytes())
    receipt["root_installations"] = 0
    path.write_bytes(canonical(receipt))
    first = ledger.reserve(IDENTITY, scope, dns, path, sha(path.read_bytes()), root_cost=0)
    assert first["operation"] == "NATIVE_DIAGNOSTIC"
    assert (first["native_used"], first["root_installations_used"]) == (1, 0)
    finish_review(ledger, first["attempt_id"])
    second = ledger.reserve(
        IDENTITY, scope, dns, path, approved(stable, batch="BATCH3", n=2), root_cost=1
    )
    assert second["operation"] == "ROOT_AND_NATIVE"
    assert (second["native_used"], second["root_installations_used"]) == (2, 1)


def test_four_operation_cost_contract_and_no_negative_costs():
    assert COSTS == dict(
        ROOT_SETUP=(0, 1), ROOT_INSTALL=(0, 1), NATIVE_DIAGNOSTIC=(1, 0), ROOT_AND_NATIVE=(1, 1)
    )
    with pytest.raises(ValueError, match="LEDGER_COST"):
        totals(
            [
                dict(
                    event="ROOT_OPERATION_RESERVED_V1",
                    operation="ROOT_SETUP",
                    native_cost=0,
                    root_cost=-1,
                )
            ]
        )


def test_global_limit_includes_setup_and_unknown_blocks():
    rows = [
        dict(
            event="ROOT_OPERATION_RESERVED_V1",
            attempt_id=str(i),
            batch="BATCH1",
            operation="ROOT_SETUP",
            native_cost=0,
            root_cost=1,
        )
        for i in range(10)
    ]
    rows += [
        dict(event="ROOT_OPERATION_FINISHED_V1", attempt_id=str(i), outcome="SUCCEEDED")
        for i in range(10)
    ]
    budget = dict(
        native_used=0, root_installations_used=0, native_max=10, root_installations_max=10
    )
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        guard_reservation(rows, dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=1), budget, None)
    rows[-1]["outcome"] = "UNKNOWN"
    with pytest.raises(ValueError, match="UNRESOLVED"):
        guard_reservation(rows, dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=0), budget, None)


def test_root_install_uses_same_accounting_without_native(setup, monkeypatch):
    from soc_agent.security_ai.ebpf_tc import installation

    scope = dict(
        operation="ROOT_INSTALL",
        root_manifest=setup.binding.artifact.root_manifest,
        installed_manifest=setup.binding.installed_manifest,
        rollback_manifest=setup.binding.rollback_manifest,
        start_native=False,
    )
    setup.binding = setup.binding.model_copy(update=dict(scope_sha=digest(scope)))
    calls = []
    monkeypatch.setattr(installation, "verify_package", lambda *a: calls.append(a))
    event = reserve(setup, operation="ROOT_INSTALL", scope=scope)
    assert len(calls) == 1 and event["operation"] == "ROOT_INSTALL"
    assert (event["native_used"], event["root_installations_used"]) == (0, 1)


@pytest.mark.parametrize("rollback", [False, True])
def test_retention_failure_never_reserves(setup, monkeypatch, rollback):
    def damaged(*a, **kw):
        if kw.get("rollback", False) == rollback:
            raise ValueError("FIXTURE_RETENTION_DAMAGED")

    monkeypatch.setattr(root, "inspect_retained", damaged)
    before = body(setup)
    with pytest.raises(ValueError, match="RETENTION_DAMAGED"):
        reserve(setup)
    assert body(setup) == before


def test_wrong_manifest_pin_is_not_a_release_upgrade(setup):
    args = setup.issue()
    data = setup.binding.model_dump()
    data["artifact"]["root_manifest"] = "f" * 64
    altered = root.RootBinding.model_validate(data)
    with pytest.raises(ValueError, match="BINDING"):
        setup.ledger.reserve_root(altered, **args)


def test_launcher_is_a_fixed_review_scope_not_a_shell_runner():
    scope = root.launcher_scope()
    assert scope["setup_argv"] == setup_proposal()["proposed_root_argv"]
    assert not scope["arbitrary_command"] and not scope["native"] and not scope["tcx"]
    assert scope["worker"]["capabilities"] == []
    assert scope["cleanup"]["delete_by_name"] is False


def test_reassessment_preview_applies_root_limits_under_same_lock(setup):
    from soc_agent.security_ai.ebpf_tc.reassessment_admission import _PreviewCampaign

    for index in range(2):
        setup.binding = setup.binding.model_copy(
            update=dict(session=f"00000000-0000-0000-0000-{index:012d}")
        )
        event = reserve(setup)
        setup.ledger.record_root(
            event["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64
        )
    preview = object.__new__(_PreviewCampaign)
    preview.directory, preview.batch = setup.ledger.directory, "BATCH3"
    preview.budget, preview.budget_body = setup.ledger.budget, setup.ledger.budget_body
    preview.baseline_body = setup.ledger.baseline_body
    before = body(setup)
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        preview._admission_transaction(
            lambda rows: dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=1)
        )
    assert body(setup) == before


def test_same_session_cannot_get_second_reservation_by_reissuing_receipt(setup):
    event = reserve(setup)
    setup.ledger.record_root(
        event["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64
    )
    before = body(setup)
    with pytest.raises(ValueError, match="SESSION_ALREADY_RESERVED"):
        reserve(setup)
    assert body(setup) == before


def test_competing_reservations_share_lock_and_only_one_wins(setup):
    from concurrent.futures import ThreadPoolExecutor

    args = setup.issue()

    def attempt():
        try:
            return setup.ledger.reserve_root(setup.binding, **args)["event"]
        except ValueError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert sorted(results) == ["ROOT_APPROVAL_REPLAY", "ROOT_OPERATION_RESERVED_V1"]
    assert totals([json.loads(line) for line in body(setup).splitlines()]) == (0, 1)


def test_dns_worker_permission_denied_precedes_any_socket_use(monkeypatch):
    from soc_agent.security_ai.ebpf_tc import isolated_dns_worker as worker
    from soc_agent.security_ai.ebpf_tc.namespace_isolation import IsolatedScope

    def denied():
        raise PermissionError("FIXTURE_CONTROLLER_PERMISSION_DENIED")

    monkeypatch.setattr(worker, "local_controller", denied)
    # Objects have no socket/context-manager methods: any use before the gate fails.
    with pytest.raises(PermissionError, match="CONTROLLER_PERMISSION_DENIED"):
        worker.serve_prebound(
            IsolatedScope(namespace="net:[4999999999]"),
            object(),
            object(),
            ready=lambda _: pytest.fail("Worker must not become ready"),
        )
