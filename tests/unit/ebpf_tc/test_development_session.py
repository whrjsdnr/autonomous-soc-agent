"""Synthetic approvals in temporary chains only; no live activation or privilege."""

import json
import time
from uuid import uuid4

import pytest
from tests.unit.ebpf_tc.test_native_campaign import IDENTITY
from tests.unit.ebpf_tc.test_native_campaign import fixture as fixture
from tests.unit.ebpf_tc.test_root_operations import package as package
from tests.unit.ebpf_tc.test_root_operations import setup as setup
from tests.unit.ebpf_tc.test_stabilization_campaign import stable as stable

from soc_agent.security_ai.ebpf_tc import development_session as dev
from soc_agent.security_ai.ebpf_tc import isolated_dns_launcher
from soc_agent.security_ai.ebpf_tc.installation import canonical
from soc_agent.security_ai.ebpf_tc.operational_recovery import main
from soc_agent.security_ai.ebpf_tc.phase_d import SCOPE
from soc_agent.security_ai.ebpf_tc.reassessment import Artifact, digest
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding, RootOperations
from soc_agent.security_ai.native_campaign import sha
from soc_agent.security_ai.operation_budget import guard_reservation, totals

NS = "net:[7777777]"


@pytest.fixture
def policy_case(stable, monkeypatch):
    directory = stable[0]
    campaign = RootOperations(directory, "BATCH3")
    artifact = Artifact(
        git_commit="1" * 40,
        git_tree="2" * 40,
        release="0.6.3",
        manifest=IDENTITY["manifest"],
        bundle=IDENTITY["bundle"],
        image=IDENTITY["image"],
        root_manifest=IDENTITY["tcx_manifest"],
    )
    origin = RootBinding(
        session=str(uuid4()),
        artifact=artifact,
        source_snapshot="3" * 64,
        scope_sha="4" * 64,
        installed_manifest="5" * 64,
        rollback_manifest="6" * 64,
    )
    policy = dev.DevelopmentPolicy(
        decision="APPROVED",
        approver="UNIT_TEST_REVIEW_ONLY",
        human_reference_sha="7" * 64,
        session=str(uuid4()),
        namespace=NS,
        lease_file=directory / "lease.json",
        lease_sha="8" * 64,
        namespace_origin=origin.model_dump(mode="json"),
        budget_sha=digest(campaign.budget),
        baseline_sha=sha(campaign.baseline_body),
        security_implementation_sha=dev.implementation_sha(),
        artifacts=[artifact],
        issued_at=int(time.time()) - 1,
        expires_at=int(time.time()) + 300,
    )
    monkeypatch.setattr(isolated_dns_launcher, "inspect_lease", lambda *_: dict(namespace=NS))
    path = directory / "dev-policy.json"
    path.write_bytes(canonical(policy.model_dump(mode="json")))
    rows = [json.loads(x) for x in (directory / "execution-ledger.jsonl").read_bytes().splitlines()]
    packet = dict(
        kind="DEVELOPMENT_METERING_POLICY_ACTIVATION",
        policy_file=str(path),
        policy_sha=sha(path.read_bytes()),
        expected_tip=rows[-1].get("record_sha256", digest(rows[-1])),
    )
    return campaign, policy, packet


def activation_rows(case):
    campaign, _, packet = case
    dev.activate(campaign, packet)
    return [
        json.loads(x)
        for x in (campaign.directory / "execution-ledger.jsonl").read_bytes().splitlines()
    ]


def event(case):
    campaign, policy, packet = case
    return dict(
        event="NATIVE_ATTEMPT_RESERVED",
        attempt_id="test-only",
        batch="BATCH3",
        scope=SCOPE | dict(namespace=NS),
        dns_scope={"namespace": NS},
        release=IDENTITY,
        git_commit=policy.artifacts[0].git_commit,
        root_cost=1,
        development_session_sha=packet["policy_sha"],
    )


def test_policy_is_dormant_without_an_activation_event(policy_case):
    c, _, _ = policy_case
    with pytest.raises(ValueError, match="NOT_ACTIVATED"):
        guard_reservation([], event(policy_case), c.budget, "BATCH3")


def test_existing_cli_activation_appends_only_policy_and_prevents_replay(policy_case):
    c, _, packet = policy_case
    before = (c.directory / "execution-ledger.jsonl").read_bytes()
    budget = c.budget_body
    path = c.directory / "activation.json"
    path.write_bytes(canonical(packet))
    assert (
        main(
            [
                "reassess",
                str(c.directory),
                "--campaign",
                str(c.directory),
                "--root-governance-file",
                str(path),
                "--root-governance-sha",
                sha(path.read_bytes()),
            ]
        )
        == 0
    )
    after = (c.directory / "execution-ledger.jsonl").read_bytes()
    assert after.startswith(before) and c.budget_body == budget
    rows = [json.loads(x) for x in after.splitlines()]
    assert len(rows) == 2 and totals(rows) == (0, 0)
    assert rows[-1]["authorizes_execution"] is False
    with pytest.raises(ValueError, match="REPLAY"):
        dev.activate(c, packet)
    assert (c.directory / "execution-ledger.jsonl").read_bytes() == after


def test_metering_retains_all_counts_past_campaign_and_batch_caps(policy_case):
    c, _, _ = policy_case
    rows = activation_rows(policy_case)
    for i in range(12):
        prior = event(policy_case) | dict(attempt_id=str(i))
        rows.extend([prior, dict(event="NATIVE_ATTEMPT_FINISHED", attempt_id=str(i))])
    value = event(policy_case)
    guard_reservation(rows, value, c.budget, "BATCH3")
    assert value["native_used"] == value["root_installations_used"] == 13
    assert value["count_policy"] == "ISOLATED_DEVELOPMENT_OBSERVE_ONLY_V1"
    legacy = dict(value)
    del legacy["development_session_sha"]
    with pytest.raises(ValueError, match="BUDGET_EXHAUSTED"):
        guard_reservation(rows, legacy, c.budget, "BATCH3")


@pytest.mark.parametrize("change", ["namespace", "events", "queue", "image", "git", "batch", "pin"])
def test_changed_scope_or_artifact_never_inherits_a_session(policy_case, change):
    c, _, _ = policy_case
    rows = activation_rows(policy_case)
    value = event(policy_case)
    batch = "BATCH3"
    if change == "namespace":
        value["scope"]["namespace"] = "net:[4026531833]"
    elif change in ("events", "queue"):
        value["scope"][change] += 1
    elif change == "image":
        value["release"] = IDENTITY | dict(image="f" * 64)
    elif change == "git":
        value["git_commit"] = "a" * 40
    elif change == "batch":
        batch = "BATCH2"
    else:
        value["development_session_sha"] = "0" * 64
    with pytest.raises(ValueError, match="DEVELOPMENT"):
        guard_reservation(rows, value, c.budget, batch)


def test_unfinished_native_blocks_even_with_metering(policy_case):
    c, _, _ = policy_case
    rows = activation_rows(policy_case) + [event(policy_case)]
    with pytest.raises(ValueError, match="CONCURRENT"):
        guard_reservation(rows, event(policy_case), c.budget, "BATCH3")


@pytest.mark.parametrize("change", ["expiry", "security", "lease", "baseline"])
def test_policy_expiry_code_changes_and_environment_fail_closed(policy_case, monkeypatch, change):
    c, _, _ = policy_case
    rows = activation_rows(policy_case)
    if change == "expiry":
        monkeypatch.setattr(dev.time, "time", lambda: 10**12)
    elif change == "security":
        monkeypatch.setattr(dev, "implementation_sha", lambda: "0" * 64)
    elif change == "lease":
        monkeypatch.setattr(
            isolated_dns_launcher, "inspect_lease", lambda *_: dict(namespace="net:[1]")
        )
    else:
        rows[0]["baseline_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="DEVELOPMENT"):
        guard_reservation(rows, event(policy_case), c.budget, "BATCH3")


def test_stale_activation_does_not_modify_chain(policy_case):
    c, _, packet = policy_case
    path = c.directory / "execution-ledger.jsonl"
    before = path.read_bytes()
    with pytest.raises(ValueError, match="STALE"):
        dev.activate(c, packet | dict(expected_tip="0" * 64))
    assert path.read_bytes() == before


def test_root_metering_does_not_charge_native(policy_case):
    c, policy, packet = policy_case
    rows = activation_rows(policy_case)
    value = dict(
        event="ROOT_OPERATION_RESERVED_V1",
        attempt_id="new",
        operation="ROOT_INSTALL",
        native_cost=0,
        root_cost=1,
        binding={"artifact": policy.artifacts[0].model_dump(mode="json")},
        scope={"operation": "ROOT_INSTALL"},
        development_namespace=NS,
        development_session_sha=packet["policy_sha"],
    )
    guard_reservation(rows, value, c.budget, "BATCH3")
    assert value["native_used"] == 0 and value["root_installations_used"] == 1
    assert totals(rows + [value]) == (0, 1)


def test_actual_root_reservation_keeps_receipt_checks_past_caps(policy_case, setup):
    """Real reserve/finish API with synthetic receipts, no Root process."""
    c, policy, packet = policy_case
    policy = policy.model_copy(update=dict(artifacts=[setup.binding.artifact]))
    path = c.directory / "dev-policy.json"
    path.write_bytes(canonical(policy.model_dump(mode="json")))
    packet = packet | dict(policy_sha=sha(path.read_bytes()))
    dev.activate(c, packet)
    for _ in range(12):
        setup.binding = setup.binding.model_copy(update=dict(session=str(uuid4())))
        scope = dict(
            operation="ROOT_INSTALL",
            root_manifest=setup.binding.artifact.root_manifest,
            installed_manifest=setup.binding.installed_manifest,
            rollback_manifest=setup.binding.rollback_manifest,
            start_native=False,
        )
        setup.binding = setup.binding.model_copy(update=dict(scope_sha=digest(scope)))
        args = setup.issue(
            "ROOT_INSTALL",
            scope=scope,
            development_session_sha=packet["policy_sha"],
            development_namespace=NS,
        )
        reserved = c.reserve_root(setup.binding, **args)
        for state in ("START_INTENT", "STARTED", "SUCCEEDED"):
            c.record_root(reserved["attempt_id"], state=state, evidence_sha="a" * 64)
    assert reserved["root_installations_used"] == 12 and reserved["native_used"] == 0
    before = (c.directory / "execution-ledger.jsonl").read_bytes()
    with pytest.raises(ValueError, match="REPLAY"):
        c.reserve_root(setup.binding, **args)
    assert (c.directory / "execution-ledger.jsonl").read_bytes() == before
