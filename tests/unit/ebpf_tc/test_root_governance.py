"""Real temporary chain/CLI, synthetic human receipts; no Root or Native work."""

import json

import pytest
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_root_operations import package as package
from tests.unit.ebpf_tc.test_root_operations import setup as setup
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import root_governance as gov
from soc_agent.security_ai.ebpf_tc import root_operations as root
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.operational_recovery import main
from soc_agent.security_ai.native_campaign import sha
from soc_agent.security_ai.operation_budget import batch_root_limit, guard_reservation, totals


def rows(s):
    return [
        json.loads(line)
        for line in (s.ledger.directory / "execution-ledger.jsonl").read_bytes().splitlines()
    ]


@pytest.fixture
def governance(setup):
    s = setup
    s.issue()
    policy = root.RootPolicy.model_validate_json(s.policy_file.read_bytes())
    review = dict(
        contract="SOC_ROOT_POLICY_AND_NAMESPACE_BUDGET_REVIEW_V1",
        binding=s.binding.model_dump(),
        policy_activation=dict(implementation_sha256=policy.implementation_sha),
        execution_request=dict(ledger_tip_sha256=gov._tip(rows(s))),
        budget=dict(B=dict(proposed_batch3_total_root_cap=3)),
    )
    path = s.ledger.directory / "review.json"
    path.write_bytes(canonical(review))
    return s, dict(
        review_file=path,
        review_sha=sha(path.read_bytes()),
        policy_file=s.policy_file,
        policy_sha=sha(s.policy_file.read_bytes()),
        expected_tip=gov._tip(rows(s)),
    )


def allocate(governance, **changes):
    s, args = governance
    event = gov.activate_policy(s.ledger, **args)
    policy = root.RootPolicy.model_validate_json(s.policy_file.read_bytes())
    data = (
        gov.RootAllocation(
            decision="APPROVED",
            approver=policy.approver,
            human_reference_sha=policy.human_reference_sha,
            approved_binding=s.binding,
            review_package_sha=args["review_sha"],
            budget_sha=sha(s.ledger.budget_body),
            baseline_sha=sha(s.ledger.baseline_body),
            ledger_tip_sha=event["record_sha256"],
            policy_record_sha=event["record_sha256"],
            issued_at=policy.issued_at,
            expires_at=policy.expires_at,
        ).model_dump()
        | changes
    )
    path = s.ledger.directory / "allocation.json"
    path.write_bytes(canonical(data))
    kw = dict(
        review_file=args["review_file"],
        review_sha=args["review_sha"],
        allocation_file=path,
        allocation_sha=sha(path.read_bytes()),
    )
    return s, kw


def test_allocation_append_only_preserves_native_and_original_budget(governance):
    s, _ = governance
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    budget = s.ledger.budget_body
    s, kw = allocate(governance)
    event = gov.allocate_root(s.ledger, **kw)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes().startswith(before)
    assert (s.ledger.directory / "budget.json").read_bytes() == budget
    assert totals(rows(s)) == (0, 0)
    assert batch_root_limit(rows(s), s.ledger.budget, "BATCH3") == 3
    assert event["authorizes_execution"] is False
    with pytest.raises(ValueError, match="REPLAY_OR_DUPLICATE"):
        gov.allocate_root(s.ledger, **kw)


def test_policy_replay_cannot_be_reactivated(governance):
    s, kw = governance
    gov.activate_policy(s.ledger, **kw)
    with pytest.raises(ValueError, match="ACTIVATION_REPLAY"):
        gov.activate_policy(s.ledger, **kw)


@pytest.mark.parametrize(
    "changes",
    [
        dict(root_max=4),
        dict(native_max=3),
        dict(campaign_root_max=11),
        dict(ledger_tip_sha="f" * 64),
        dict(policy_record_sha="f" * 64),
        dict(expires_at=1),
        dict(human_reference_sha="f" * 64),
        dict(approver="OTHER_REVIEWER"),
        dict(refund=True),
        dict(budget_sha="f" * 64),
    ],
)
def test_invalid_budget_decision_does_not_append(governance, changes):
    s, kw = allocate(governance, **changes)
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError):
        gov.allocate_root(s.ledger, **kw)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_three_root_slots_and_native_unchanged_under_allocation(governance):
    s, kw = allocate(governance)
    gov.allocate_root(s.ledger, **kw)
    history = rows(s)
    # Pure proposals use the same locked-writer guard without any execution.
    for index, kind in enumerate(["ROOT_SETUP", "ROOT_INSTALL", "ROOT_INSTALL"]):
        event = dict(
            event="ROOT_OPERATION_RESERVED_V1",
            attempt_id=str(index),
            batch="BATCH3",
            operation=kind,
            native_cost=0,
            root_cost=1,
        )
        guard_reservation(history, event, s.ledger.budget, "BATCH3")
        history += [
            event,
            dict(event="ROOT_OPERATION_FINISHED_V1", attempt_id=str(index), outcome="SUCCEEDED"),
        ]
        assert event["native_used"] == 0 and event["root_installations_used"] == index + 1
    with pytest.raises(ValueError, match="SUBALLOCATION|BUDGET_EXHAUSTED"):
        guard_reservation(
            history,
            dict(event="ROOT_OPERATION_RESERVED_V1", operation="ROOT_INSTALL"),
            s.ledger.budget,
            "BATCH3",
        )
    assert totals(rows(s)) == (0, 0)


def test_native_diagnostic_ignores_setup_cost_but_counts_installation(governance):
    s, kw = allocate(governance)
    gov.allocate_root(s.ledger, **kw)
    history = rows(s) + [
        dict(
            event="ROOT_OPERATION_RESERVED_V1",
            attempt_id="setup",
            operation="ROOT_SETUP",
            batch="BATCH3",
            native_cost=0,
            root_cost=1,
        ),
        dict(event="ROOT_OPERATION_FINISHED_V1", attempt_id="setup", outcome="SUCCEEDED"),
    ]
    event = dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=0)
    guard_reservation(history, event, s.ledger.budget, "BATCH3")
    assert (event["native_used"], event["root_installations_used"]) == (1, 1)


def test_campaign_limit_stays_ten(governance):
    s, kw = allocate(governance)
    gov.allocate_root(s.ledger, **kw)
    history = rows(s) + [
        dict(event="NATIVE_ATTEMPT_RESERVED", attempt_id=str(i), batch="BATCH1", root_cost=1)
        for i in range(10)
    ]
    with pytest.raises(ValueError, match="CAMPAIGN_BUDGET_EXHAUSTED"):
        guard_reservation(
            history,
            dict(event="ROOT_OPERATION_RESERVED_V1", operation="ROOT_SETUP"),
            s.ledger.budget,
            "BATCH3",
        )


def test_expired_grant_never_refunds_or_renews(governance, monkeypatch):
    s, kw = allocate(governance)
    event = gov.allocate_root(s.ledger, **kw)
    monkeypatch.setattr(
        "soc_agent.security_ai.operation_budget.time.time",
        lambda: event["allocation"]["expires_at"] + 1,
    )
    assert batch_root_limit(rows(s), s.ledger.budget, "BATCH3") == 2
    assert totals(rows(s)) == (0, 0)


def test_existing_cli_records_policy_and_refuses_execute_mode(governance, capsys):
    s, args = governance
    packet = dict(
        kind="ROOT_POLICY_ACTIVATION",
        review_file=str(args["review_file"]),
        review_sha=args["review_sha"],
        policy_file=str(args["policy_file"]),
        policy_sha=args["policy_sha"],
        expected_tip=args["expected_tip"],
    )
    p = s.ledger.directory / "packet.json"
    p.write_bytes(canonical(packet))
    pin = sha(p.read_bytes())
    cli = [
        "reassess",
        str(s.ledger.directory),
        "--campaign",
        str(s.ledger.directory),
        "--root-governance-file",
        str(p),
        "--root-governance-sha",
        pin,
    ]
    assert main(cli) == 0
    assert json.loads(capsys.readouterr().out)["event"] == "ROOT_POLICY_ACTIVATED_V1"
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    cli[0] = "execute"
    assert main(cli) != 0
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_wrong_policy_binding_or_manifest_is_not_activated(governance):
    s, kwargs = governance
    data = json.loads(s.policy_file.read_bytes())
    data["binding"]["artifact"]["root_manifest"] = "f" * 64
    s.policy_file.write_bytes(canonical(data))
    kwargs["policy_sha"] = sha(s.policy_file.read_bytes())
    with pytest.raises(ValueError, match="REVIEW_BINDING"):
        gov.activate_policy(s.ledger, **kwargs)


@pytest.mark.parametrize("target", ["session", "release", "manifest", "source"])
def test_exact_binding_changes_cannot_activate_policy(governance, target):
    s, kwargs = governance
    data = json.loads(s.policy_file.read_bytes())
    if target == "session":
        data["binding"]["session"] = "00000000-0000-0000-0000-000000000001"
    elif target == "source":
        data["binding"]["source_snapshot"] = "f" * 64
    else:
        data["binding"]["artifact"][target] = "9.9.9" if target == "release" else "f" * 64
    s.policy_file.write_bytes(canonical(data))
    kwargs["policy_sha"] = sha(s.policy_file.read_bytes())
    before = (s.ledger.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="REVIEW_BINDING"):
        gov.activate_policy(s.ledger, **kwargs)
    assert (s.ledger.directory / "execution-ledger.jsonl").read_bytes() == before


def test_missing_policy_file_and_stale_policy_tip_fail_closed(governance):
    s, kwargs = governance
    bad = kwargs | dict(policy_file=s.ledger.directory / "does-not-exist")
    with pytest.raises(FileNotFoundError):
        gov.activate_policy(s.ledger, **bad)
    # Correct tip in the reviewed package, but a new unrelated event makes it stale.
    s.ledger._locked(lambda _: dict(event="FIXTURE_NEW_LEDGER_EVENT"))
    with pytest.raises(ValueError, match="STALE_LEDGER"):
        gov.activate_policy(s.ledger, **kwargs)


def test_actual_root_api_retains_one_install_after_setup(governance):
    s, kw = allocate(governance)
    gov.allocate_root(s.ledger, **kw)
    setup_event = s.ledger.reserve_root(s.binding, **s.issue())
    assert (setup_event["native_used"], setup_event["root_installations_used"]) == (0, 1)
    # No Root action: this synthetic cancellation closes the test reservation, no refund.
    s.ledger.record_root(
        setup_event["attempt_id"], state="CANCELLED_BEFORE_EXECUTION", evidence_sha="a" * 64
    )
    # One historical installation plus the charged setup leaves the third slot for installation.
    hist = rows(s) + [
        dict(event="NATIVE_ATTEMPT_RESERVED", attempt_id="old-install", batch="BATCH3", root_cost=1)
    ]
    candidate = dict(event="NATIVE_ATTEMPT_RESERVED", root_cost=1)
    guard_reservation(hist, candidate, s.ledger.budget, "BATCH3")
    assert (candidate["native_used"], candidate["root_installations_used"]) == (2, 3)
