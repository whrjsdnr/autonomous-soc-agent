"""Snapshot transactions and full ownership equality over a foreign shared clsact fixture."""

import pytest
from tests.ebpf_broker_support import plan, run

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_broker.engine import Engine


def engine():
    records = []
    e = Engine(plan(), lambda kind, **detail: records.append((kind, detail)), lambda: None)
    e.execute(Command(command="PREPARE", plan_digest=e.plan.identity, sequence=1))
    return e, records


def attach(e):
    return e.execute(
        Command(
            command="ATTACH",
            plan_digest=e.plan.identity,
            sequence=e.sequence + 1,
            run=run(e.plan, e.run_count + 1),
        )
    )


def test_transaction_records_before_after_and_preserves_shared_qdisc_and_filters():
    e, records = engine()
    before = e.registry.snapshot()
    attach(e)
    assert e.state == "ATTACH_PENDING" and not e.snapshot()["native_active"]
    owner = e.owner
    e.execute(Command(command="DETACH", ownership=owner, plan_digest=e.plan.identity, sequence=3))
    assert e.registry.snapshot() == before and e.owner is None
    assert e.state == "CLOSED"
    assert [k for k, _ in records] == [
        "BROKER_READY",
        "ATTACH_REQUESTED",
        "ATTACH_VERIFIED",
        "STOP_REQUESTED",
        "DETACH_REQUESTED",
        "DETACH_VERIFIED",
        "CLEANUP_VERIFIED",
    ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("program_id", 999),
        ("program_tag", "b" * 16),
        ("ifindex", 77),
        ("namespace", "net:[999]"),
        ("hook", "EGRESS"),
        ("handle", 88),
    ],
)
def test_mismatched_ownership_never_removes_filter(field, value):
    e, _ = engine()
    attach(e)
    before = e.registry.snapshot()
    bad = e.owner.model_copy(update={field: value})
    with pytest.raises(ValueError, match="OWNERSHIP_MISMATCH"):
        e.execute(Command(command="DETACH", ownership=bad, plan_digest=e.plan.identity, sequence=3))
    assert e.registry.snapshot() == before


def test_foreign_replacement_must_be_left_orphaned_not_force_deleted():
    e, records = engine()
    attach(e)
    key = e.registry.key(e.owner)
    e.registry.filters[key] = "OTHER_PROCESS_REPLACED_THIS_SLOT"
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        e.cleanup_owned("USER_STOP")
    assert e.registry.filters[key] == "OTHER_PROCESS_REPLACED_THIS_SLOT"
    assert e.cleanup == "ORPHANED_OR_CLEANUP_UNVERIFIED" and e.state == "ERROR"
    assert any(k == "CLEANUP_UNVERIFIED" for k, _ in records)


def test_collision_and_unsupported_qdisc_have_no_side_effect():
    e, _ = engine()
    r = run(e.plan)
    key = ("INGRESS", 0, 49152, r.capture_session.int & 0xFFFFFFFF)
    e.registry.filters[key] = "EXISTING_FILTER"
    before = e.registry.snapshot()
    with pytest.raises(ValueError, match="COLLISION"):
        e.registry.attach(e.plan, r, e.record)
    assert e.registry.snapshot() == before
    e.registry.qdisc = "existing_other_qdisc"
    with pytest.raises(ValueError, match="QDISC_UNSUPPORTED"):
        e.registry.attach(e.plan, run(e.plan), e.record)
    assert e.registry.qdisc == "existing_other_qdisc"


def test_partial_attach_audit_failure_rolls_back_exact_owned_slot():
    e, _ = engine()
    before = e.registry.snapshot()

    def fail(kind, **details):
        if kind == "ATTACH_VERIFIED":
            raise OSError("fixture disk failure")

    with pytest.raises(OSError):
        e.registry.attach(e.plan, run(e.plan), fail)
    assert e.registry.snapshot() == before


def test_partial_detach_without_final_evidence_remains_unverified():
    e, _ = engine()
    attach(e)

    def fail(kind, **details):
        if kind == "DETACH_VERIFIED":
            raise OSError("fixture disk failure")

    e.record = fail
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        e.cleanup_owned("USER_STOP")
    assert e.owner is not None and e.registry.key(e.owner) not in e.registry.filters
    assert e.cleanup == "ORPHANED_OR_CLEANUP_UNVERIFIED"


@pytest.mark.parametrize("change", ["sequence", "plan_digest", "run_scope"])
def test_replay_wrong_session_and_scope_are_rejected(change):
    e, _ = engine()
    data = dict(command="ATTACH", plan_digest=e.plan.identity, sequence=2, run=run(e.plan))
    if change == "run_scope":
        data["run"] = data["run"].model_copy(update={"scope_digest": "f" * 64})
    elif change == "sequence":
        data["sequence"] = 1
    else:
        data["plan_digest"] = "f" * 64
    before = e.registry.snapshot()
    with pytest.raises(ValueError):
        e.execute(Command(**data))
    assert e.registry.snapshot() == before


@pytest.mark.parametrize("reason", ["GUI_CLOSE", "CONTROLLER_EXIT", "SIGINT", "SIGTERM", "TIMEOUT"])
def test_explicit_stop_reasons_and_no_duplicate_detach(reason):
    e, records = engine()
    attach(e)
    e.execute(Command(command="STOP", reason=reason, plan_digest=e.plan.identity, sequence=3))
    e.execute(Command(command="STOP", reason=reason, plan_digest=e.plan.identity, sequence=4))
    assert e.owner is None and sum(k == "DETACH_VERIFIED" for k, _ in records) == 1


def test_timeout_heartbeat_controller_loader_failure_and_no_automatic_restart():
    e, _ = engine()
    attach(e)
    e.last_heartbeat = e.run_started + 300
    e.tick(e.run_started + 300)
    assert e.owner is None and e.state == "CLOSED" and e.run_count == 1
    with pytest.raises(ValueError, match="HEARTBEAT_TIMEOUT"):
        e.tick(e.last_heartbeat + 15)

    def crash():
        raise ValueError("BROKER_LOADER_CRASH_FIXTURE")

    e.validate = crash
    with pytest.raises(ValueError, match="LOADER_CRASH"):
        e.tick(e.last_heartbeat)
    assert e.run_count == 1


def test_same_capture_or_generation_cannot_be_replayed_with_next_run_number():
    e, _ = engine()
    first = run(e.plan)
    e.execute(Command(command="ATTACH", plan_digest=e.plan.identity, sequence=2, run=first))
    e.execute(Command(command="STOP", reason="USER_STOP", plan_digest=e.plan.identity, sequence=3))
    replay = first.model_copy(update={"run_number": 2})
    with pytest.raises(ValueError, match="RUN_SCOPE_OR_SEQUENCE"):
        e.execute(Command(command="ATTACH", plan_digest=e.plan.identity, sequence=4, run=replay))
    assert e.run_count == 1 and e.state == "ERROR"


def test_partial_attach_foreign_race_is_not_reported_clean():
    e, _ = engine()
    before = e.registry.snapshot()

    def race(kind, **details):
        if kind == "ATTACH_VERIFIED":
            key = e.registry.key(e.registry.pending_owner)
            e.registry.filters[key] = "UNKNOWN_OWNER"
            raise OSError("fixture concurrent filter replacement")

    e.record = race
    with pytest.raises(OSError):
        attach(e)
    assert e.owner is not None and e.state == "ERROR"
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        e.cleanup_owned("CONTROLLER_EXIT")
    assert e.cleanup == "ORPHANED_OR_CLEANUP_UNVERIFIED"
    assert e.registry.qdisc == before["qdisc"]
    assert all(v in e.registry.filters.values() for v in ["FOREIGN_INGRESS", "FOREIGN_EGRESS"])
