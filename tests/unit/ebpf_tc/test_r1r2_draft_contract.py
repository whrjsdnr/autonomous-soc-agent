"""Unapproved contract simulations, separate from real Native/Root acceptance."""

import copy
from dataclasses import asdict

import pytest
from pydantic import ValidationError
from tests.r1r2_draft_spec import (
    Artifact,
    Binding,
    Context,
    DraftSchedule,
    Evidence,
    History,
    Receipt,
    ScenarioScope,
    sha,
    simulate_review,
    simulated_latest_decision,
)
from tests.unit.ebpf.test_batch1_flow import packet
from tests.unit.ebpf_tc.test_batch2_window import complete

from soc_agent.security_ai.collectors.packet_producer import FlowAssembly
from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint
from soc_agent.security_ai.ebpf.input_eligibility import input_receipts
from soc_agent.security_ai.ebpf_tc.capture_evidence import assess_capture


def proposed():
    artifact = Artifact(
        release="SYNTHETIC_ONLY",
        manifest="1" * 64,
        bundle="2" * 64,
        image="3" * 64,
        root_manifest="4" * 64,
    )
    evidence = Evidence(
        fd_closed=True,
        maps_remaining=0,
        links_remaining=0,
        filters_remaining=0,
        container_absent=True,
        drain_verified=True,
        new_unknown_programs=0,
        foreign_attach_owner="ATTRIBUTED_EXTERNAL",
        external_removal_cause="UNKNOWN",
    )
    binding = Binding(
        attempt="fixture-attempt",
        prior_session="fixture-prior-session",
        prior_generation=2**63 + 1,
        prior_artifact=artifact,
        next_session="fixture-next-session",
        next_artifact=artifact,
        negative_review_sha="5" * 64,
        evidence_manifest_sha=sha(evidence.model_dump()),
        scope_sha="6" * 64,
        procedure_sha="7" * 64,
    )
    ctx = Context(
        procedure_approved_in_fixture=True,
        reviewer="fixture-operator",
        trusted_human_reference_sha="8" * 64,
        binding=binding,
        evidence=evidence,
        now=15,
    )
    history = History()
    receipt = Receipt(
        receipt_id="fixture-receipt",
        reviewer=ctx.reviewer,
        human_reference_sha=ctx.trusted_human_reference_sha,
        binding=binding,
        ledger_tip_sha=history.tip,
        decision="ALLOW_NEXT_ADMISSION_ONLY",
        accept_unknown_external_removal_cause=True,
        issued_at=10,
        expires_at=20,
    )
    ctx = ctx.model_copy(update=dict(trusted_receipt_sha=sha(receipt.model_dump())))
    return receipt, ctx, history


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "unapproved",
        "human",
        "session",
        "release",
        "scope",
        "sha",
        "stale",
        "expired",
        "future",
    ],
)
def test_review_failures_do_not_change_history(mutation):
    receipt, ctx, history = proposed()
    if mutation == "missing":
        receipt = None
    elif mutation == "unapproved":
        ctx = ctx.model_copy(update=dict(procedure_approved_in_fixture=False))
    elif mutation == "human":
        receipt = receipt.model_copy(update=dict(human_reference_sha="9" * 64))
    elif mutation in {"session", "release", "scope", "sha"}:
        updates = {
            "session": dict(prior_session="other"),
            "release": dict(
                next_artifact=receipt.binding.next_artifact.model_copy(update=dict(release="other"))
            ),
            "scope": dict(scope_sha="9" * 64),
            "sha": dict(negative_review_sha="9" * 64),
        }
        receipt = receipt.model_copy(
            update=dict(binding=receipt.binding.model_copy(update=updates[mutation]))
        )
    elif mutation == "stale":
        receipt = receipt.model_copy(update=dict(ledger_tip_sha="9" * 64))
    elif mutation == "expired":
        ctx = ctx.model_copy(update=dict(now=20))
    elif mutation == "future":
        ctx = ctx.model_copy(update=dict(now=9))
    before = copy.deepcopy(history)
    with pytest.raises(ValueError):
        simulate_review(receipt, ctx, history)
    assert history == before and history.original_failed and history.original_safe is False


@pytest.mark.parametrize(
    "changes",
    [
        dict(fd_closed=False),
        dict(maps_remaining=1),
        dict(links_remaining=1),
        dict(filters_remaining=1),
        dict(container_absent=False),
        dict(drain_verified=False),
        dict(new_unknown_programs=1),
        dict(foreign_attach_owner="UNKNOWN"),
    ],
)
def test_cleanup_or_unknown_ownership_cannot_be_overridden(changes):
    receipt, ctx, history = proposed()
    e = ctx.evidence.model_copy(update=changes)
    binding = ctx.binding.model_copy(update=dict(evidence_manifest_sha=sha(e.model_dump())))
    ctx = ctx.model_copy(update=dict(evidence=e, binding=binding))
    receipt = receipt.model_copy(update=dict(binding=binding))
    ctx = ctx.model_copy(update=dict(trusted_receipt_sha=sha(receipt.model_dump())))
    with pytest.raises(ValueError, match="OWNED_CLEANUP_OR_OWNERSHIP_UNPROVEN"):
        simulate_review(receipt, ctx, history)
    assert not history.events


def test_unknown_external_trigger_requires_explicit_risk_acceptance_not_global_pass():
    receipt, ctx, history = proposed()
    with pytest.raises(ValueError, match="UNCERTAINTY_NOT_ACCEPTED"):
        unaccepted = receipt.model_copy(update=dict(accept_unknown_external_removal_cause=False))
        simulate_review(
            unaccepted,
            ctx.model_copy(update=dict(trusted_receipt_sha=sha(unaccepted.model_dump()))),
            history,
        )
    result = simulate_review(receipt, ctx, history)
    assert result.original_failed and result.original_safe is False
    assert not history.events and result.events[0].kind == "SPEC_ONLY_REASSESSMENT"
    assert "safe_for_next_attempt" not in asdict(result.events[0])
    assert simulated_latest_decision(result) == "ALLOW_NEXT_ADMISSION_ONLY"


def test_duplicate_replay_stale_approval_and_latest_denial():
    receipt, ctx, history = proposed()
    result = simulate_review(receipt, ctx, history)
    with pytest.raises(ValueError, match="REPLAY"):
        simulate_review(receipt, ctx, result)
    duplicate = receipt.model_copy(update=dict(receipt_id="new-id", ledger_tip_sha=result.tip))
    with pytest.raises(ValueError, match="APPROVAL_ALREADY_USED"):
        simulate_review(
            duplicate,
            ctx.model_copy(update=dict(trusted_receipt_sha=sha(duplicate.model_dump()))),
            result,
        )
    ctx = ctx.model_copy(update=dict(trusted_human_reference_sha="9" * 64))
    deny = receipt.model_copy(
        update=dict(
            receipt_id="denial",
            human_reference_sha="9" * 64,
            ledger_tip_sha=result.tip,
            decision="DENY",
        )
    )
    ctx = ctx.model_copy(update=dict(trusted_receipt_sha=sha(deny.model_dump())))
    result = simulate_review(deny, ctx, result)
    assert simulated_latest_decision(result) == "DENY"
    assert result.events[1].previous == History(events=result.events[:1]).tip
    assert result.original_failed and result.original_safe is False


@pytest.mark.parametrize("updates", [dict(manifest="wrong"), dict(image="A" * 64)])
def test_malformed_artifact_sha_rejected(updates):
    artifact = proposed()[0].binding.next_artifact.model_dump()
    artifact.update(updates)
    with pytest.raises(ValidationError):
        Artifact(**artifact)


@pytest.mark.parametrize(
    "updates",
    [
        dict(authorize_root_execution=True),
        dict(override_global_guard=True),
        dict(max_next_attempts=2),
    ],
)
def test_draft_receipt_cannot_grant_execution_or_override(updates):
    data = proposed()[0].model_dump()
    data.update(updates)
    with pytest.raises(ValidationError):
        Receipt(**data)


def test_r2_virtual_35_45_second_schedule_is_independent_of_closed_sidecar():
    s = DraftSchedule(ScenarioScope(), fixture_scope_approved=True)
    assert (
        s.tick(39_999_999_999, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=12)
        == "SPEC_ONLY_WAIT"
    )
    assert (
        s.tick(40_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=12)
        == "SPEC_ONLY_REQUEST_ONE_UDP_WITNESS"
    )
    assert (
        s.tick(41_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=14)
        == "SPEC_ONLY_WAIT"
    )
    assert (
        s.tick(50_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=14)
        == "SPEC_ONLY_NORMAL_STOP"
    )
    assert s.scope.sidecar_deadline == 10 and s.scope.duration_max == 300
    assert (
        s.tick(51_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=14)
        == "SPEC_ONLY_ALREADY_STOPPED"
    )


def test_r2_is_inactive_without_approved_scope_and_cannot_extend_sidecar():
    s = DraftSchedule(ScenarioScope())
    with pytest.raises(ValueError, match="NOT_APPROVED"):
        s.tick(40_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=12)
    s.fixture_scope_approved = True
    with pytest.raises(ValueError, match="SIDECAR_NOT_CLOSED"):
        s.tick(40_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=False, received=12)
    assert not s.witness_requested


@pytest.mark.parametrize("time_ns,count", [(13_000_000_000, 4096), (60_000_000_000, 12)])
def test_cap_or_capture_plan_stops_without_late_witness(time_ns, count):
    s = DraftSchedule(ScenarioScope(), fixture_scope_approved=True)
    assert (
        s.tick(time_ns, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=count)
        == "SPEC_ONLY_NORMAL_STOP_INCOMPLETE"
    )
    assert not s.witness_requested


@pytest.mark.parametrize(
    "updates",
    [
        dict(udp_total=1),
        dict(udp_total=3),
        dict(target="8.8.8.8:53"),
        dict(namespace="net:[99]"),
        dict(interface="eth0"),
        dict(events_max=4097),
        dict(sidecar_deadline=35),
        dict(witness_retries=1),
    ],
)
def test_legacy_or_expanded_unapproved_scope_is_rejected(updates):
    with pytest.raises(ValidationError):
        ScenarioScope(**updates)


def fixture_pipeline(witness_ns):
    summary, _, windows, samples, counters, delivery = complete()
    flow = FlowAssembly("session", compact=True, event_watermark=True)
    flow.add(packet(1, 1000, flags=1))
    flow.add(packet(2, 2000, flags=1, reverse=True))
    if witness_ns is not None:
        flow.add(packet(3, witness_ns, kind="udp", port=222))
    flow.finish("CAPTURE_STOP")
    n = 2 if witness_ns is None else 3
    summary.update(feature_tail=flow.finalized, received=n, accepted=n)
    summary["cpu_sequence"]["intervals"]["0"].update(received=n, last_ns=witness_ns or 2000)
    counters["delivered"] = n
    counters["totals"].update(observed=n, emitted=n)
    delivery.update(callbacks=n, delivered=n)
    for row in windows:
        if row["phase"] == "POST_DETACH":
            row["before_ns"] += 10_000_000_000
            row["after_ns"] += 10_000_000_000
            if row["cpu"] == 0:
                row["counters"].update(observed=n, emitted=n)
    for sample in samples:
        if sample["phase"] == 2:
            for k in ("before_ns", "wall_ns", "after_ns"):
                sample[k] += 10_000_000_000
    capture = assess_capture(
        counters,
        delivery,
        summary,
        closed=True,
        error=None,
        source=2,
        scope=dict(program_sha256="a" * 64, approval_digest="b" * 64),
        cpu_windows=windows,
        clock_samples=samples,
    )
    assert capture["status"] == "VERIFIED"
    return summary, input_receipts(summary, dict(capture_evidence=capture))


@pytest.mark.parametrize(
    "witness_ns,eligible", [(None, False), (29_999_999_000, False), (35_000_002_000, True)]
)
def test_actual_flow_contract_needs_captured_event_not_scheduler_time(witness_ns, eligible):
    summary, receipts = fixture_pipeline(witness_ns)
    assert receipts[0]["eligible"] is eligible
    assert all(r["source"] == "FIXTURE_NOT_NATIVE" and not r["model_executed"] for r in receipts)
    text = encode_checkpoint(summary)
    assert len(text.encode()) <= 16384 and decode_checkpoint(text) == summary
    lifecycle = summary["feature_tail"][0]["lifecycle"]
    assert lifecycle["bidirectional"] and lifecycle["tcp_termination"] == "BOTH_FIN_OBSERVED"
    if eligible:
        assert lifecycle["timeout_witness_ns"] == witness_ns
        assert summary["feature_tail"][0]["close_reason"] == "IDLE_TIMEOUT"
    else:
        assert receipts[0]["flow_completion"] == "INCOMPLETE"


@pytest.mark.parametrize("updates", [dict(tcp_total=True), dict(udp_total=2.0)])
def test_numeric_scope_literals_are_not_bool_or_float(updates):
    with pytest.raises(ValidationError):
        ScenarioScope(**updates)


@pytest.mark.parametrize(
    "updates", [dict(max_next_attempts=True), dict(authorize_root_execution=0)]
)
def test_review_literal_types_are_exact(updates):
    data = proposed()[0].model_dump()
    data.update(updates)
    with pytest.raises(ValidationError):
        Receipt(**data)


def test_next_session_and_artifact_digest_are_bound():
    receipt, ctx, history = proposed()
    for binding in (
        receipt.binding.model_copy(update=dict(next_session="different")),
        receipt.binding.model_copy(
            update=dict(
                next_artifact=receipt.binding.next_artifact.model_copy(
                    update=dict(manifest="9" * 64)
                )
            )
        ),
    ):
        with pytest.raises(ValueError, match="BINDING_MISMATCH"):
            simulate_review(receipt.model_copy(update=dict(binding=binding)), ctx, history)
    assert not history.events


def test_tampered_cleanup_bytes_do_not_match_evidence_manifest():
    receipt, ctx, history = proposed()
    ctx = ctx.model_copy(
        update=dict(evidence=ctx.evidence.model_copy(update=dict(fd_closed=False)))
    )
    with pytest.raises(ValueError, match="MANIFEST_MISMATCH"):
        simulate_review(receipt, ctx, history)
    assert not history.events


def test_simulator_is_not_imported_by_production_and_has_no_runtime_io():
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    assert all("r1r2_draft_spec" not in p.read_text() for p in (root / "src").rglob("*.py"))
    source = (root / "tests/r1r2_draft_spec.py").read_text()
    tree = ast.parse(source)
    names = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert not names & {"open", "exec", "eval", "__import__"}
    imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any(n and n.startswith("soc_agent") for n in imports)


def test_whole_receipt_digest_is_pinned_by_trusted_fixture_approval():
    receipt, ctx, history = proposed()
    tampered = receipt.model_copy(update=dict(decision="DENY"))
    with pytest.raises(ValueError, match="RECEIPT_SHA_MISMATCH"):
        simulate_review(tampered, ctx, history)
    assert not history.events


def test_r1_review_does_not_grant_r2_or_native_execution():
    receipt, ctx, history = proposed()
    scope = ScenarioScope()
    binding = ctx.binding.model_copy(update=dict(scope_sha=sha(scope.model_dump())))
    receipt = receipt.model_copy(update=dict(binding=binding))
    ctx = ctx.model_copy(
        update=dict(binding=binding, trusted_receipt_sha=sha(receipt.model_dump()))
    )
    history = simulate_review(receipt, ctx, history)
    assert simulated_latest_decision(history) == "ALLOW_NEXT_ADMISSION_ONLY"
    schedule = DraftSchedule(scope)
    with pytest.raises(ValueError, match="SCOPE_NOT_APPROVED"):
        schedule.tick(40_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=12)
    assert not receipt.authorize_root_execution and not receipt.override_global_guard


def test_two_approvals_cannot_reuse_a_stale_history_tip():
    receipt, ctx, history = proposed()
    latest = simulate_review(receipt, ctx, history)
    second = receipt.model_copy(update=dict(receipt_id="second", human_reference_sha="9" * 64))
    ctx = ctx.model_copy(
        update=dict(
            trusted_human_reference_sha="9" * 64, trusted_receipt_sha=sha(second.model_dump())
        )
    )
    with pytest.raises(ValueError, match="STALE_TIP"):
        simulate_review(second, ctx, latest)
    assert len(latest.events) == 1


def test_missed_witness_deadline_does_not_send_it_late_or_mark_completion():
    s = DraftSchedule(ScenarioScope(), fixture_scope_approved=True)
    assert (
        s.tick(50_000_000_000, tcp_closed_ns=5_000_000_000, sidecar_closed=True, received=12)
        == "SPEC_ONLY_NORMAL_STOP_INCOMPLETE"
    )
    assert not s.witness_requested


def test_late_tcp_close_cannot_extend_capture_plan():
    s = DraftSchedule(ScenarioScope(), fixture_scope_approved=True)
    assert (
        s.tick(59_000_000_000, tcp_closed_ns=30_000_000_000, sidecar_closed=True, received=12)
        == "SPEC_ONLY_WAIT"
    )
    assert (
        s.tick(60_000_000_000, tcp_closed_ns=30_000_000_000, sidecar_closed=True, received=12)
        == "SPEC_ONLY_NORMAL_STOP_INCOMPLETE"
    )
    assert not s.witness_requested


def test_draft_cannot_inject_a_real_campaign_event_or_shorten_delay():
    data = proposed()[0].model_dump()
    data["safe_for_next_attempt"] = True
    with pytest.raises(ValidationError):
        Receipt(**data)
    with pytest.raises(ValidationError):
        ScenarioScope(witness_delay_ns=30_000_000_000)
