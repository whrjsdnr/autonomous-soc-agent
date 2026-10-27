"""Batch transition on real temporary chains; synthetic approvals, never Native evidence."""

import json
import time
from pathlib import Path

import pytest
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_r1r2_operational import activate_fixture, artifact, h, rewrite_receipt
from tests.unit.ebpf_tc.test_r1r2_operational import review as review
from tests.unit.ebpf_tc.test_stabilization_campaign import approved
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import reassessment as r1
from soc_agent.security_ai.ebpf_tc import reassessment_admission as admission
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.native_campaign import NativeCampaign
from soc_agent.security_ai.stabilization_campaign import StabilizationCampaign


@pytest.fixture
def transition(review, stable):
    original_review = review["receipt_file"].read_bytes()
    adapter, path, scope, dns = activate_fixture(review, stable)
    a = artifact()
    identity = dict(
        manifest=a.manifest, bundle=a.bundle, image=a.image, tcx_manifest=a.root_manifest
    )
    pending = adapter.reserve(identity, scope, dns, path, h(path.read_bytes()), root_cost=1)
    settlement = NativeCampaign._locked(
        adapter,
        lambda rows: dict(
            event="EXECUTION_RESERVATION_SETTLED_V1",
            attempt_id=pending["attempt_id"],
            disposition="EVIDENCE_INCOMPLETE",
            root="UNKNOWN",
            native="UNKNOWN",
            budget_action="KEEP_RESERVATION_CHARGE",
            approval_reusable=False,
            authorizes_execution=False,
        ),
    )
    review["receipt_file"] = adapter.directory / "batch3-review.json"
    review["receipt_file"].write_bytes(original_review)
    review["campaign"] = StabilizationCampaign(adapter.directory, "BATCH3")
    binding = r1.Binding.model_validate(
        review["expected_binding"].model_dump() | dict(batch="BATCH3", next_session="batch3-next")
    )
    review["expected_binding"] = binding
    p = review["procedure_file"]
    data = json.loads(p.read_bytes()) | dict(binding_sha=r1.digest(binding.model_dump()))
    p.write_bytes(canonical(data))
    review["procedure_sha"] = h(p.read_bytes())
    rewrite_receipt(
        review,
        receipt_id="SYNTHETIC_BATCH3_REVIEW",
        human_reference_sha="6" * 64,
        binding=binding.model_dump(),
        procedure_sha=review["procedure_sha"],
        ledger_tip_sha=settlement["record_sha256"],
        accepted_settlements={pending["attempt_id"]: settlement["record_sha256"]},
    )
    return review, stable, settlement, identity


def prepare(transition, *, accept=True, allocate=True):
    review, stable, settlement, identity = transition
    if not accept:
        rewrite_receipt(review, accepted_settlements={})
    event = r1.reassess(**review)
    ledger = review["campaign"]
    allocation = admission.BatchAllocation(
        decision="APPROVED",
        approver="SYNTHETIC_BUDGET_OWNER",
        human_reference_sha="5" * 64,
        batch="BATCH3",
        budget_sha=h(ledger.budget_body),
        baseline_sha=h(ledger.baseline_body),
        expires_at=int(time.time()) + 600,
    )
    amendment = admission.AdmissionAmendment(
        decision="APPROVED",
        approver="SYNTHETIC_POLICY_OWNER",
        human_reference_sha="4" * 64,
        implementation_sha=h(Path(admission.__file__).read_bytes()),
        base_controller_sha=ledger.controller_sha,
        budget_sha=h(ledger.budget_body),
        baseline_sha=h(ledger.baseline_body),
        binding=review["expected_binding"],
        reassessment_record_sha=event["record_sha256"],
        review_receipt_sha=review["receipt_sha"],
        expires_at=int(time.time()) + 600,
        activate_versioned_admission=True,
        batch_allocation=allocation if allocate else None,
    )
    p = ledger.directory / "batch3-amendment.json"
    p.write_bytes(canonical(amendment.model_dump()))
    args = dict(amendment_file=p, amendment_sha=h(p.read_bytes()))
    approved(stable, "BATCH3", 3)
    execution = json.loads(stable[1].read_bytes()) | dict(
        admission_amendment_sha=args["amendment_sha"],
        next_session="batch3-next",
        reassessment_record_sha=event["record_sha256"],
        r2_receipt_sha="e" * 64,
    )
    stable[1].write_bytes(canonical(execution))
    return ledger, args, identity, execution


def test_batch3_preview_retains_unknown_charge_and_false(transition):
    ledger, args, identity, _ = prepare(transition)
    path = ledger.directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    stable = transition[1]
    result = admission.preview_reservation(
        ledger.directory,
        **args,
        identity=identity,
        scope=stable[2],
        dns_scope=stable[3],
        approval_file=stable[1],
        approval_sha=h(stable[1].read_bytes()),
        root_cost=1,
        git_commit=artifact().git_commit,
    )
    assert result["native_used_if_reserved"] == result["root_used_if_reserved"] == 3
    assert path.read_bytes() == before
    adapter = admission.ReassessedCampaign(ledger.directory, **args)
    event = adapter.reserve(
        identity, stable[2], stable[3], stable[1], h(stable[1].read_bytes()), root_cost=1
    )
    assert event["batch"] == "BATCH3" and event["native_used"] == 3
    rows = [json.loads(x) for x in path.read_bytes().splitlines()]
    assert [r["batch"] for r in rows if r["event"] == "NATIVE_ATTEMPT_RESERVED"] == [
        "BATCH2",
        "BATCH2",
        "BATCH3",
    ]
    assert any(r.get("safe_for_next_attempt") is False for r in rows)
    assert transition[2] in rows  # Accounting UNKNOWN remains byte-equivalent, no refund.
    with pytest.raises(ValueError, match="ALREADY_CONSUMED"):
        adapter.reserve(
            identity, stable[2], stable[3], stable[1], h(stable[1].read_bytes()), root_cost=1
        )


def test_batch3_without_budget_grant_blocked(transition):
    ledger, args, *_ = prepare(transition, allocate=False)
    with pytest.raises(ValueError, match="BATCH_ALLOCATION_REQUIRED"):
        admission.ReassessedCampaign(ledger.directory, **args)


def test_settlement_is_not_implicit_risk_acceptance(transition):
    ledger, args, identity, _ = prepare(transition, accept=False)
    stable = transition[1]
    before = (ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="PRIOR_ATTEMPT_UNFINISHED"):
        admission.preview_reservation(
            ledger.directory,
            **args,
            identity=identity,
            scope=stable[2],
            dns_scope=stable[3],
            approval_file=stable[1],
            approval_sha=h(stable[1].read_bytes()),
            root_cost=1,
            git_commit=artifact().git_commit,
        )
    assert (ledger.directory / "execution-ledger.jsonl").read_bytes() == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("root", "NOT_STARTED"),
        ("approval_reusable", True),
        ("budget_action", "REFUND"),
        ("record_sha256", "0" * 64),
    ],
)
def test_review_rejects_different_settlement_evidence(transition, field, value):
    review, _, settlement, _ = transition
    with pytest.raises(ValueError, match="SETTLEMENT_RISK_BINDING"):
        r1.validate_settlement_acceptances(
            [settlement | {field: value}], {settlement["attempt_id"]: settlement["record_sha256"]}
        )
    assert review["expected_binding"].batch == "BATCH3"


def test_batch3_allocation_expiry_checked_after_confirmation(transition, monkeypatch):
    ledger, args, *_ = prepare(transition)
    adapter = admission.ReassessedCampaign(ledger.directory, **args)
    monkeypatch.setattr(admission.time, "time", lambda: 2**40)
    stable = transition[1]
    with pytest.raises(ValueError, match="EXPIRED"):
        adapter.reserve(
            transition[3], stable[2], stable[3], stable[1], h(stable[1].read_bytes()), root_cost=1
        )


def test_actual_reassess_cli_uses_explicit_batch3_binding(transition, capsys):
    from soc_agent import cli

    review, _, _, _ = transition
    p = review["campaign"].directory / "batch3-evidence-packet.json"
    p.write_bytes(
        canonical(
            dict(
                binding=review["expected_binding"].model_dump(),
                evidence=review["evidence"].model_dump(),
                source_paths={k: str(v) for k, v in review["source_paths"].items()},
            )
        )
    )
    before = (review["campaign"].directory / "execution-ledger.jsonl").read_bytes()
    assert (
        cli.main(
            [
                "native-recovery",
                "reassess",
                str(p.parent),
                "--campaign",
                str(p.parent),
                "--procedure-file",
                str(review["procedure_file"]),
                "--procedure-sha",
                review["procedure_sha"],
                "--review-file",
                str(review["receipt_file"]),
                "--review-sha",
                review["receipt_sha"],
                "--evidence-file",
                str(p),
                "--evidence-sha",
                h(p.read_bytes()),
            ]
        )
        == 0
    )
    event = json.loads(capsys.readouterr().out)
    assert event["binding"]["batch"] == "BATCH3"
    assert event["accepted_settlements"] and event["authorizes_execution"] is False
    assert (p.parent / "execution-ledger.jsonl").read_bytes().startswith(before)


@pytest.mark.parametrize(
    "field,value", [("budget_sha", "0" * 64), ("baseline_sha", "0" * 64), ("expires_at", 1)]
)
def test_invalid_batch3_allocation_rejected(transition, field, value):
    ledger, args, *_ = prepare(transition)
    p = args["amendment_file"]
    value_dict = json.loads(p.read_bytes())
    value_dict["batch_allocation"][field] = value
    p.write_bytes(canonical(value_dict))
    with pytest.raises(ValueError, match="ALLOCATION_REQUIRED"):
        admission.ReassessedCampaign(
            ledger.directory, amendment_file=p, amendment_sha=h(p.read_bytes())
        )
