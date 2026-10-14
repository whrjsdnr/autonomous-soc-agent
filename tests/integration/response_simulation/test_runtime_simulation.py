"""Fixture collector transport with actual runtime, policy, approval and private SQLite."""

import asyncio
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.execution.errors import (
    ApprovalRejectedError,
    ApprovalRequiredError,
    ExecutionDeniedError,
)
from soc_agent.linux_runtime.response_simulation import RuntimeResponseSimulation
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.state.evidence import utc_now


async def prepared(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    monitor.simulation.set_enabled(True)
    await monitor.tick()
    await monitor.investigate_one()
    monitor.simulation.prepare_completed()
    return root, monitor, monitor.simulation.records()[0]


@pytest.mark.asyncio
async def test_default_disabled_and_requires_completed_investigation(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)
    assert not monitor.simulation.enabled()
    await monitor.tick()
    assert monitor.simulation.records() == ()
    with pytest.raises(ValueError, match="DISABLED"):
        monitor.simulation.request("0" * 64)
    monitor.simulation.set_enabled(True)
    with pytest.raises(ValueError, match="FINDING_MISSING"):
        monitor.simulation.request("0" * 64)


@pytest.mark.asyncio
async def test_pending_review_then_explicit_simulation_and_restart(tmp_path, monkeypatch):
    root, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    assert record.status == "PENDING_REVIEW"
    assert record.simulated_handler_calls == 0
    with pytest.raises(ApprovalRequiredError):
        await monitor.simulation.execute(identity)
    with pytest.raises(ValueError, match="TEST_REVIEWER"):
        monitor.simulation.review(identity, approve=True, test_reviewer="pretend-production-user")
    with pytest.raises(ValueError, match="DECISION_REJECTED"):
        monitor.simulation.review(identity, approve="false", test_reviewer="test:operator")
    approved = monitor.simulation.review(identity, approve=True, test_reviewer="test:operator")
    assert approved.actor_assurance == "EXPLICIT_TEST_IDENTITY"
    assert approved.request == record.request
    restarted = LinuxMonitor(root)
    done = await restarted.simulation.execute(identity)
    assert done.status == "SIMULATED"
    assert done.output.simulated and not done.output.real_system_modified
    assert done.simulated_handler_calls == 1 and done.real_os_handler_calls == 0
    latest = LinuxMonitor(root)
    latest.simulation.recover()
    assert latest.simulation.load(identity) == done
    with pytest.raises(ValueError, match="ALREADY_ATTEMPTED"):
        await latest.simulation.execute(identity)
    assert latest.store.verify_audit()


@pytest.mark.asyncio
async def test_rejection_and_approval_replay(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=False, test_reviewer="test:reviewer")
    with pytest.raises(ApprovalRejectedError):
        await monitor.simulation.execute(identity)
    with pytest.raises(ValueError, match="ALREADY_DECIDED"):
        monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    assert monitor.simulation.load(identity).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_expiry_boundaries_and_restored_expired_approval(tmp_path, monkeypatch):
    _, monitor, _ = await prepared(tmp_path, monkeypatch)
    current = [utc_now()]
    simulation = RuntimeResponseSimulation(
        monitor.store, monitor.pipeline, clock=lambda: current[0]
    )
    record = simulation.records()[0]
    simulation.review(record.request.candidate_id, approve=True, test_reviewer="test:clock")
    record = simulation.load(record.request.candidate_id)
    current[0] = record.approval.expires_at - timedelta(microseconds=1)
    executor, _ = simulation._executor(record.approval)
    executor.preflight(record.request.action, approval_id=record.approval.approval_id)
    current[0] += timedelta(microseconds=1)
    for instance in (
        simulation,
        RuntimeResponseSimulation(monitor.store, monitor.pipeline, clock=lambda: current[0]),
    ):
        with pytest.raises(ExecutionDeniedError, match="expired"):
            await instance.execute(record.request.candidate_id)
    assert simulation.load(record.request.candidate_id).simulated_handler_calls == 0


@pytest.mark.parametrize("change", ["TARGET", "INCIDENT", "ACTION_ID"])
@pytest.mark.asyncio
async def test_bound_action_changes_denied(tmp_path, monkeypatch, change):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    action = record.request.action.model_copy(
        update=(
            {"tool_input": '{"account_id":"demo-bob"}'}
            if change == "TARGET"
            else {"incident_id": uuid4()}
            if change == "INCIDENT"
            else {"action_id": uuid4()}
        )
    )
    with pytest.raises(ExecutionDeniedError, match="binding changed"):
        await monitor.simulation.execute(identity, action=action)
    assert monitor.simulation.load(identity).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_policy_change_after_approval_denied(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")

    class Deny(PolicyEngine):
        def evaluate(self, metadata):
            return PolicyResult(decision=PolicyDecision.DENY, reason="fixture current policy")

    simulation = RuntimeResponseSimulation(monitor.store, monitor.pipeline, policy=Deny())
    with pytest.raises(ExecutionDeniedError):
        await simulation.execute(identity)
    assert simulation.load(identity).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_evidence_tampering_missing_source_and_audit_guard(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    with monitor.pipeline.store.database.transaction() as c:
        c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError):
        await monitor.simulation.execute(identity)
    assert monitor.simulation.load(identity).simulated_handler_calls == 0
    with monitor.store.database.transaction() as c:
        c.execute(
            "UPDATE monitor_audit SET digest=? WHERE sequence="
            "(SELECT max(sequence) FROM monitor_audit)",
            ("0" * 64,),
        )
    with pytest.raises(ValueError, match="AUDIT_INTEGRITY"):
        monitor.simulation.load(identity)


@pytest.mark.asyncio
async def test_audit_failure_prevents_pure_handler_and_reservation(tmp_path, monkeypatch):
    root, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    original = monitor.store._audit
    calls = []
    from soc_agent.demo import tools

    async def spy(value):
        calls.append(value)
        return await original_handler(value)

    original_handler = tools.simulate_disable
    monkeypatch.setattr(tools, "simulate_disable", spy)

    def fault(*args):
        raise OSError("Fixture audit unavailable")

    monkeypatch.setattr(monitor.store, "_audit", fault)
    with pytest.raises(OSError):
        await monitor.simulation.execute(identity)
    assert calls == []
    restored = RuntimeResponseSimulation(RuntimeStore(root), monitor.pipeline)
    assert restored.load(identity).status == "APPROVED"
    monkeypatch.setattr(monitor.store, "_audit", original)


@pytest.mark.asyncio
async def test_duplicate_execution_race_has_one_pure_call(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    results = await asyncio.gather(
        monitor.simulation.execute(identity),
        monitor.simulation.execute(identity),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    assert monitor.simulation.load(identity).simulated_handler_calls == 1
    assert monitor.simulation.load(identity).real_os_handler_calls == 0


@pytest.mark.asyncio
async def test_changed_window_blocks_approved_simulation_without_stopping_collection(
    tmp_path, monkeypatch
):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    from tests.unit.operational_features.test_native_authentication import row

    from soc_agent.security_ai.operational.native_authentication import project_journal

    event = project_journal(row(99, 20), include_pam_failures=True)
    monitor.pipeline.queue.enqueue(event)
    monitor.pipeline.step()
    monitor.simulation.prepare_completed()  # Existing request does not stop monitoring.
    with pytest.raises(ValueError, match="EVIDENCE_OR_INCIDENT_CHANGED"):
        await monitor.simulation.execute(identity)
    assert monitor.simulation.load(identity).simulated_handler_calls == 0


@pytest.mark.asyncio
async def test_expiry_race_between_reservation_and_dispatch_has_zero_calls(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    record = monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    clock_values = iter(
        (record.approval.expires_at - timedelta(microseconds=1), record.approval.expires_at)
    )
    simulation = RuntimeResponseSimulation(
        monitor.store, monitor.pipeline, clock=lambda: next(clock_values)
    )
    from soc_agent.demo import tools

    calls = []
    original = tools.simulate_disable

    async def spy(value):
        calls.append(value)
        return await original(value)

    monkeypatch.setattr(tools, "simulate_disable", spy)
    with pytest.raises(ExecutionDeniedError, match="expired"):
        await simulation.execute(identity)
    assert calls == []
    simulation.recover()
    assert simulation.load(identity).status == "UNCERTAIN"
    assert simulation.load(identity).simulated_handler_calls is None


@pytest.mark.asyncio
async def test_missing_evidence_and_finding_receipt_rejected(tmp_path, monkeypatch):
    _, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id
    monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    with monitor.pipeline.store.database.transaction() as c:
        c.execute("DELETE FROM operational_sources")
    with pytest.raises((ValueError, KeyError)):
        await monitor.simulation.execute(identity)
    assert monitor.simulation.load(identity).simulated_handler_calls == 0


def test_cli_mutation_takes_runtime_lock_before_opening_pipeline(tmp_path, monkeypatch, capsys):
    import sys

    from soc_agent.linux_runtime import __main__ as cli
    from soc_agent.runtime_lock import exclusive_runtime_lock

    root, monitor = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["monitor", "--directory", str(root), "simulation", "enable"])

    def forbidden(*args):
        raise AssertionError("Pipeline must not open while another runtime owns the writer lock")

    monkeypatch.setattr(cli, "open_pipeline", forbidden)
    with exclusive_runtime_lock(root / "writer.lock"):
        assert cli.main() == 1
    assert not monitor.simulation.enabled()
    assert json.loads(capsys.readouterr().out)["health"] == "FAILED"


@pytest.mark.asyncio
async def test_rejected_inputs_do_not_copy_sensitive_text_into_audit(tmp_path, monkeypatch):
    _, monitor, _ = await prepared(tmp_path, monkeypatch)
    secret = "fixture-secret-not-a-candidate-or-reviewer"
    with pytest.raises(ValueError, match="CANDIDATE_ID"):
        await monitor.simulation.execute(secret)
    with pytest.raises(ValueError, match="CANDIDATE_ID"):
        monitor.simulation.review(secret, approve=True, test_reviewer=secret)
    with monitor.store.database.transaction(write=False) as c:
        text = "\n".join(row[0] for row in c.execute("SELECT payload FROM monitor_audit"))
    assert secret not in text
    assert "SIMULATION_REVIEW_DENIED" in text


@pytest.mark.asyncio
async def test_review_audit_failure_never_persists_approval(tmp_path, monkeypatch):
    root, monitor, record = await prepared(tmp_path, monkeypatch)
    identity = record.request.candidate_id

    def fault(*args):
        raise OSError("fixture unavailable audit")

    monkeypatch.setattr(monitor.store, "_audit", fault)
    with pytest.raises(OSError):
        monitor.simulation.review(identity, approve=True, test_reviewer="test:reviewer")
    restored = RuntimeResponseSimulation(RuntimeStore(root), monitor.pipeline)
    assert restored.load(identity).status == "PENDING_REVIEW"
    assert restored.load(identity).approval.decision is None
