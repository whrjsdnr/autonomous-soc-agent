"""Unprivileged lifecycle/CLI/settlement failure injection; no real campaign writes."""

import json
import os
import signal
import time
from pathlib import Path

import pytest
from pydantic import ValidationError
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import activate_fixture, h
from tests.unit.ebpf_tc.test_r1r2_operational import review as review
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent import cli
from soc_agent.review.persistence.secure_storage import StorageSecurityError
from soc_agent.security_ai.ebpf_tc import execution_management as management
from soc_agent.security_ai.ebpf_tc.execution_request import ExecutionRequest, load_request
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.termination import SupervisorTermination, termination_boundary


@pytest.fixture
def controlled(review, stable, tmp_path):
    adapter, approval, scope, dns = activate_fixture(review, stable)
    binding = adapter.amendment.binding
    receipt = management.ManagementApproval(
        decision="APPROVED",
        approver="SYNTHETIC_NOT_HUMAN_APPROVAL",
        human_reference_sha="a" * 64,
        binding=binding,
        implementation_sha=management.implementation_sha(),
        budget_sha=h(adapter.budget_body),
        baseline_sha=h(adapter.baseline_body),
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 600,
        activate_delayed_reservation=True,
    )
    policy = tmp_path / "policy.json"
    policy.write_bytes(canonical(receipt.model_dump()))
    journal = management.LifecycleJournal.create(
        tmp_path / "journal", management.digest(binding.model_dump()), binding.next_session
    )
    control = management.ExecutionControl(
        journal,
        lambda: {"attempt_id": "fixture-attempt"},
        policy_file=policy,
        policy_sha=h(policy.read_bytes()),
        campaign=adapter,
        binding=binding,
    )
    return control, adapter, approval, scope, dns, policy


@pytest.mark.parametrize(
    "phase,root,native,disposition",
    [
        ("BEFORE_CONFIRM", "NOT_STARTED", "NOT_STARTED", "CANCELLED_BEFORE_EXECUTION"),
        ("SCOPE_REJECT", "NOT_STARTED", "NOT_STARTED", "CANCELLED_BEFORE_EXECUTION"),
        ("RESERVED", "NOT_STARTED", "NOT_STARTED", "CANCELLED_BEFORE_EXECUTION"),
        ("AUTHENTICATING", "UNKNOWN", "UNKNOWN", "UNKNOWN"),
        ("ROOT_INSTALLATION_VERIFIED", "STARTED", "NOT_STARTED", "FAILED"),
        ("NATIVE_START_INTENT", "STARTED", "UNKNOWN", "FAILED"),
        ("NATIVE_CAPTURE_STARTED", "STARTED", "STARTED", "FAILED"),
    ],
)
def test_interrupt_boundaries(controlled, phase, root, native, disposition):
    control, adapter, *_ = controlled
    before = (adapter.directory / "execution-ledger.jsonl").read_bytes()
    with control:
        control.waiting()
        if phase not in {"BEFORE_CONFIRM", "SCOPE_REJECT"}:
            control.confirmed()
            for step in [
                "AUTHENTICATING",
                "ROOT_INSTALLATION_VERIFIED",
                "NATIVE_START_INTENT",
                "NATIVE_CAPTURE_STARTED",
            ]:
                if phase == "RESERVED":
                    break
                control.step(step)
                if step == phase:
                    break
        result = control.journal.end(failed=True)
    assert (result["root"], result["native"], result["disposition"]) == (root, native, disposition)
    assert (adapter.directory / "execution-ledger.jsonl").read_bytes() == before


def test_reserve_only_after_confirmation_and_duplicate_launcher(controlled):
    control, *_ = controlled
    calls = []
    control.reserve = lambda: calls.append("reserved") or {"attempt_id": "test"}
    with control:
        assert not calls
        assert control.journal.outcome()["disposition"] == "AWAITING_USER_CONFIRMATION"
        with pytest.raises(BlockingIOError):
            with management.ExecutionControl(
                control.journal,
                control.reserve,
                policy_file=control.policy_file,
                policy_sha=control.policy_sha,
                campaign=control.campaign,
                binding=control.binding,
            ):
                pass
        control.confirmed()
        assert calls == ["reserved"]
    with pytest.raises(ValueError, match="ALREADY_CLAIMED"):
        with control:
            pass


def test_restart_and_missing_or_corrupt_evidence(controlled, monkeypatch, tmp_path):
    control, *_ = controlled
    with control:
        control.confirmed()
    monkeypatch.setattr(management, "alive", lambda _: False)
    reopened = management.LifecycleJournal(control.journal.directory)
    assert not reopened.owner_alive()
    assert reopened.outcome()["disposition"] == "CANCELLED_BEFORE_EXECUTION"
    with reopened.database.transaction() as c:
        c.execute("UPDATE lifecycle SET sha=? WHERE sequence=0", ("0" * 64,))
    with pytest.raises(ValueError, match="JOURNAL_INTEGRITY"):
        management.LifecycleJournal(control.journal.directory)
    with pytest.raises((ValueError, OSError, StorageSecurityError)):
        management.LifecycleJournal(tmp_path / "missing")


def test_expiry_during_human_wait_never_reserves(controlled, monkeypatch):
    control, *_ = controlled
    calls = []
    control.reserve = lambda: calls.append(1)
    with control:
        monkeypatch.setattr(management.time, "time", lambda: 2**40)
        with pytest.raises(ValueError, match="POLICY_BINDING"):
            control.confirmed()
    assert not calls


def test_hup_uses_existing_signal_cleanup_boundary(controlled):
    control, *_ = controlled
    previous = signal.getsignal(signal.SIGHUP)
    with control:
        with pytest.raises(SupervisorTermination) as caught:
            with termination_boundary():
                os.kill(os.getpid(), signal.SIGHUP)
        assert caught.value.signum == signal.SIGHUP
        assert control.journal.end(failed=True)["disposition"] == "CANCELLED_BEFORE_EXECUTION"
    assert signal.getsignal(signal.SIGHUP) == previous


def settlement_packet(controlled, tmp_path):
    control, adapter, *_ = controlled
    a = adapter.amendment.binding.next_artifact
    # Existing reservation validators, real temporary campaign only.
    approval = controlled[2]
    scope = controlled[3]
    dns = controlled[4]
    reservation = adapter.reserve(
        dict(manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest),
        scope,
        dns,
        approval,
        h(approval.read_bytes()),
        root_cost=1,
    )
    control.reserve = lambda: reservation
    with control:
        control.confirmed()
        observed = control.journal.end(failed=True)
    evidence = dict(
        attempt_id=reservation["attempt_id"],
        disposition="CANCELLED_BEFORE_EXECUTION",
        root="NOT_STARTED",
        native="NOT_STARTED",
        verified_write_ahead_no_auth=True,
        journal_directory=str(control.journal.directory),
        journal_sha=observed["journal_sha"],
    )
    ep = tmp_path / "evidence.json"
    ep.write_bytes(canonical(evidence))
    ledger = adapter.directory / "execution-ledger.jsonl"
    before = ledger.read_bytes()
    rows = [json.loads(x) for x in before.splitlines()]
    receipt = management.SettlementApproval(
        decision="APPROVED",
        approver="SYNTHETIC",
        human_reference_sha="a" * 64,
        attempt_id=reservation["attempt_id"],
        implementation_sha=management.implementation_sha(),
        management_policy_sha=h(control.policy_file.read_bytes()),
        ledger_tip_sha=rows[-1]["record_sha256"],
        evidence_sha=h(ep.read_bytes()),
        disposition="CANCELLED_BEFORE_EXECUTION",
        root="NOT_STARTED",
        native="NOT_STARTED",
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 300,
    )
    rp = tmp_path / "settlement.json"
    rp.write_bytes(canonical(receipt.model_dump()))
    return adapter, reservation, ledger, before, receipt, rp, ep


def test_settlement_requires_human_receipt_and_never_refunds(controlled, tmp_path):
    adapter, reservation, ledger, before, receipt, rp, ep = settlement_packet(controlled, tmp_path)
    event = management.settle(
        adapter,
        receipt_file=rp,
        receipt_sha=h(rp.read_bytes()),
        evidence_file=ep,
        evidence_sha=h(ep.read_bytes()),
        policy_file=controlled[0].policy_file,
        policy_sha=controlled[0].policy_sha,
    )
    assert event["approval_reusable"] is False
    assert event["budget_action"] == "KEEP_RESERVATION_CHARGE"
    assert ledger.read_bytes().startswith(before)
    after = ledger.read_bytes()
    with pytest.raises(ValueError, match="STALE_LEDGER"):
        management.settle(
            adapter,
            receipt_file=rp,
            receipt_sha=h(rp.read_bytes()),
            evidence_file=ep,
            evidence_sha=h(ep.read_bytes()),
            policy_file=controlled[0].policy_file,
            policy_sha=controlled[0].policy_sha,
        )
    assert ledger.read_bytes() == after
    assert (
        management.inspect_reservation(adapter, reservation["attempt_id"])["root"] == "NOT_STARTED"
    )
    for key in ["refund_budget", "reuse_approval"]:
        with pytest.raises(ValidationError):
            management.SettlementApproval.model_validate(receipt.model_dump() | {key: True})


def test_legacy_absence_is_not_cancellation(controlled):
    _, adapter, *_ = controlled
    rows = [
        json.loads(x)
        for x in (adapter.directory / "execution-ledger.jsonl").read_bytes().splitlines()
    ]
    old = next(x for x in rows if x["event"] == "NATIVE_ATTEMPT_RESERVED")
    result = management.inspect_reservation(adapter, old["attempt_id"])
    assert result["root"] == result["native"] == "UNKNOWN"
    assert not result["approval_reusable"]


def test_pinned_request_cannot_override_or_embed_commands(tmp_path):
    fields = dict(
        directory=str(tmp_path),
        manifest="a" * 64,
        image_sha="b" * 64,
        campaign=str(tmp_path / "campaign"),
        amendment_file=str(tmp_path / "amendment"),
        amendment_sha="c" * 64,
        approval_file=str(tmp_path / "approval"),
        approval_sha="d" * 64,
        traffic_file=str(tmp_path / "traffic"),
        traffic_sha="e" * 64,
        claim_file=str(tmp_path / "claim"),
    )
    p = tmp_path / "request.json"
    p.write_bytes(canonical(fields))
    assert load_request(p, h(p.read_bytes()), tmp_path)["manifest"] == "a" * 64
    with pytest.raises(ValidationError):
        ExecutionRequest.model_validate(fields | {"command": "sudo"})
    with pytest.raises(ValueError):
        load_request(p, "0" * 64, tmp_path)
    with pytest.raises(ValueError):
        load_request(p, h(p.read_bytes()), tmp_path / "other")


def test_actual_cli_inspection_never_appends(controlled, capsys):
    _, adapter, *_ = controlled
    ledger = adapter.directory / "execution-ledger.jsonl"
    before = ledger.read_bytes()
    old = next(
        json.loads(x)
        for x in before.splitlines()
        if json.loads(x)["event"] == "NATIVE_ATTEMPT_RESERVED"
    )
    assert (
        cli.main(
            [
                "native-recovery",
                "check",
                str(adapter.directory),
                "--campaign",
                str(adapter.directory),
                "--attempt-id",
                old["attempt_id"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["root"] == "UNKNOWN"
    assert ledger.read_bytes() == before


@pytest.mark.parametrize("stop_at", ["confirmation", "auth", "root", "native", "complete"])
def test_managed_existing_supervisor_dispatch(controlled, tmp_path, monkeypatch, stop_at):
    from soc_agent.security_ai.ebpf_tc import phase_d, reassessment_admission

    control, adapter, approval, scope, dns, policy = controlled
    stage = tmp_path / "managed-stage"
    stage.mkdir()
    before = (adapter.directory / "execution-ledger.jsonl").read_bytes()
    a = adapter.amendment.binding.next_artifact

    def reserve():
        return adapter.reserve(
            dict(manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest),
            scope,
            dns,
            approval,
            h(approval.read_bytes()),
            root_cost=1,
        )

    def supervisor(directory, manifest, image, *, gui, r2_approval, execution_control):
        assert (adapter.directory / "execution-ledger.jsonl").read_bytes() == before
        execution_control.waiting()
        if stop_at == "confirmation":
            raise ValueError("SYNTHETIC_SCOPE_REJECTED")
        execution_control.confirmed()
        execution_control.step("AUTHENTICATING")
        if stop_at == "auth":
            raise PermissionError("SYNTHETIC_AUTH_CANCEL")
        execution_control.step("ROOT_INSTALLATION_VERIFIED")
        if stop_at == "root":
            raise OSError("SYNTHETIC_ROOT_EXIT")
        execution_control.step("NATIVE_START_INTENT")
        execution_control.step("NATIVE_CAPTURE_STARTED")
        if stop_at == "native":
            raise OSError("SYNTHETIC_NATIVE_EXIT")
        result = dict(cleanup_status="PROCESS_AND_AUDIT_VERIFIED", broker_session=a.release)
        (directory / "supervised-result.json").write_bytes(canonical(result))
        return result

    monkeypatch.setattr(phase_d, "execute", supervisor)

    def run():
        return reassessment_admission._managed_execution(
            stage,
            a.manifest,
            a.image,
            ledger=adapter,
            launch=None,
            reserve=reserve,
            management_file=policy,
            management_sha=h(policy.read_bytes()),
        )

    if stop_at == "complete":
        assert run()["execution_management"]["disposition"] == "COMPLETED"
    else:
        with pytest.raises((ValueError, OSError)):
            run()
    rows = [
        json.loads(x)
        for x in (adapter.directory / "execution-ledger.jsonl").read_bytes().splitlines()
    ]
    if stop_at == "confirmation":
        assert (adapter.directory / "execution-ledger.jsonl").read_bytes() == before
    else:
        assert rows[-1]["event"] == "NATIVE_ATTEMPT_FINISHED"
        assert rows[-1]["evidence"]["root"] == ("UNKNOWN" if stop_at == "auth" else "STARTED")
    journal = management.LifecycleJournal(stage / "execution-management")
    assert journal.outcome()["native"] == (
        "NOT_STARTED"
        if stop_at in {"confirmation", "root"}
        else "UNKNOWN"
        if stop_at == "auth"
        else "STARTED"
    )
    with pytest.raises(FileExistsError):
        run()


def test_actual_cli_no_settlement_without_pinned_human_receipt(controlled, capsys, tmp_path):
    _, adapter, *_ = controlled
    ledger = adapter.directory / "execution-ledger.jsonl"
    before = ledger.read_bytes()
    assert (
        cli.main(
            [
                "native-recovery",
                "reassess",
                str(tmp_path),
                "--campaign",
                str(adapter.directory),
                "--settlement-file",
                str(tmp_path / "missing.json"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "EXECUTION_SETTLEMENT_APPROVAL_REQUIRED"
    assert ledger.read_bytes() == before


def test_policy_binding_and_refund_flags_rejected(controlled):
    control, *_ = controlled
    body = json.loads(control.policy_file.read_bytes())
    for key in ["authorize_root", "authorize_native", "refund_budget", "reuse_consumed_approval"]:
        with pytest.raises(ValidationError):
            management.ManagementApproval.model_validate(body | {key: True})
    with pytest.raises(ValueError):
        management.verify_policy(control.policy_file, "0" * 64, control.campaign, control.binding)


def test_old_receipt_still_consumed_after_read_only_inspection(controlled):
    _, adapter, approval, scope, dns, *_ = controlled
    a = adapter.amendment.binding.next_artifact
    identity = dict(
        manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
    )
    reserved = adapter.reserve(
        identity, scope, dns, approval, h(approval.read_bytes()), root_cost=1
    )
    management.inspect_reservation(adapter, reserved["attempt_id"])
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        adapter.reserve(identity, scope, dns, approval, h(approval.read_bytes()), root_cost=1)


def test_reboot_changes_owner_epoch(controlled, monkeypatch):
    control, *_ = controlled
    with control:
        control.waiting()
    original = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return "DIFFERENT_SYNTHETIC_BOOT"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    assert not control.journal.owner_alive()
    assert control.journal.outcome()["disposition"] == "CANCELLED_BEFORE_EXECUTION"


@pytest.mark.parametrize("change", ["expired", "wrong_evidence", "missing_journal"])
def test_settlement_failures_leave_ledger_untouched(controlled, tmp_path, change):
    adapter, _, ledger, before, receipt, rp, ep = settlement_packet(controlled, tmp_path)
    if change == "expired":
        rp.write_bytes(canonical(receipt.model_dump() | {"expires_at": int(time.time()) - 1}))
    elif change == "wrong_evidence":
        ep.write_bytes(canonical(json.loads(ep.read_bytes()) | {"native": "STARTED"}))
    else:
        evidence = json.loads(ep.read_bytes())
        evidence.pop("journal_directory")
        ep.write_bytes(canonical(evidence))
        rp.write_bytes(canonical(receipt.model_dump() | {"evidence_sha": h(ep.read_bytes())}))
    with pytest.raises(ValueError):
        management.settle(
            adapter,
            receipt_file=rp,
            receipt_sha=h(rp.read_bytes()),
            evidence_file=ep,
            evidence_sha=h(ep.read_bytes()),
            policy_file=controlled[0].policy_file,
            policy_sha=controlled[0].policy_sha,
        )
    assert ledger.read_bytes() == before


def test_interrupted_settlement_append_is_not_repaired(controlled, tmp_path, monkeypatch):
    from soc_agent.security_ai import native_campaign

    adapter, _, ledger, before, _, rp, ep = settlement_packet(controlled, tmp_path)
    write = os.write
    calls = []

    def partial(fd, data):
        if calls:
            raise OSError("SYNTHETIC_CRASH_DURING_APPEND")
        calls.append(1)
        return write(fd, data[:16])

    with monkeypatch.context() as patch:
        patch.setattr(native_campaign.os, "write", partial)
        with pytest.raises(OSError):
            management.settle(
                adapter,
                receipt_file=rp,
                receipt_sha=h(rp.read_bytes()),
                evidence_file=ep,
                evidence_sha=h(ep.read_bytes()),
                policy_file=controlled[0].policy_file,
                policy_sha=controlled[0].policy_sha,
            )
    partial_bytes = ledger.read_bytes()
    assert partial_bytes.startswith(before) and partial_bytes != before
    with pytest.raises(ValueError, match="FRAMING"):
        management.inspect_reservation(adapter, json.loads(before.splitlines()[-1])["attempt_id"])
    assert ledger.read_bytes() == partial_bytes


def test_settlement_policy_activation_is_required(controlled, tmp_path):
    _, adapter, *_ = controlled
    ledger = adapter.directory / "execution-ledger.jsonl"
    before = ledger.read_bytes()
    with pytest.raises(ValueError, match="EXECUTION_MANAGEMENT_POLICY_REQUIRED"):
        management.settle(
            adapter,
            receipt_file=tmp_path / "not-a-grant",
            receipt_sha="0" * 64,
            evidence_file=tmp_path / "no-evidence",
            evidence_sha="1" * 64,
        )
    assert ledger.read_bytes() == before
