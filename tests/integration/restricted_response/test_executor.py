"""WSL/Linux filesystem effects and kernel peer credentials; authentication input is Fixture."""

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import timedelta

import pytest
from tests.authentication_crash_harness import security_check
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.linux_runtime.operator import OperatorServer, operator_request
from soc_agent.linux_runtime.restricted_models import RestrictedInput
from soc_agent.linux_runtime.restricted_resource import AVAILABLE, QUARANTINED
from soc_agent.linux_runtime.restricted_response import RestrictedResponseExecutor
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.policy import PolicyDecision, PolicyEngine, PolicyResult
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view


async def prepare(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    executor = RestrictedResponseExecutor(monitor)
    with exclusive_runtime_lock(root / "writer.lock"):
        registration = executor.enable_test_mode(test_mode=True)
        await monitor.tick()
        await monitor.investigate_one()
    assert not monitor.simulation.enabled()
    with monitor.store.database.transaction(write=False) as c:
        finding = c.execute("SELECT id FROM monitor_findings ORDER BY id").fetchone()[0]
    return root, monitor, finding, registration


@asynccontextmanager
async def endpoint(tmp_path, monkeypatch):
    root, monitor, finding, registration = await prepare(tmp_path, monkeypatch)
    with exclusive_runtime_lock(root / "writer.lock"):
        monitor.store.update(state="RUNNING")
        server = OperatorServer(monitor, (os.geteuid(),))
        await server.start()
        try:
            yield root, monitor, finding, registration, server
        finally:
            await server.close()
            monitor.store.update(state="STOPPED")


async def request(root, finding, original=None):
    result = await operator_request(
        root,
        "restricted-request" if original is None else "restricted-rollback-request",
        finding_id=finding,
        **({"candidate_id": original} if original else {}),
    )
    assert result["ok"], result
    return result["result"]


async def command(root, operation, record):
    return await operator_request(
        root,
        "restricted-" + operation,
        candidate_id=record["record"]["candidate_id"],
        expected_digest=record["record_digest"],
    )


async def approved(root, finding):
    candidate = await request(root, finding)
    result = await command(root, "approve", candidate)
    assert result["ok"]
    return result["result"]


@pytest.mark.asyncio
async def test_actual_test_file_change_separate_rollback_approval_and_restart(
    tmp_path, monkeypatch
):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        marker = root / "test-resources/marker"
        original_evidence = read_authentication_view(monitor.pipeline)
        pending = await request(root, finding)
        assert marker.read_bytes() == AVAILABLE
        assert not (await command(root, "execute", pending))["ok"]
        assert (await request(root, finding)) == pending
        approval = await command(root, "approve", pending)
        assert approval["ok"]
        done = await command(root, "execute", approval["result"])
        assert done["ok"] and done["result"]["status"] == "TEST_RESOURCE_CHANGED"
        assert marker.read_bytes() == QUARANTINED
        receipt = done["result"]["record"]["receipt"]
        assert receipt["output"]["actual_test_filesystem_change"]
        assert receipt["operator_uid"] == os.geteuid()
        assert not receipt["output"]["os_security_configuration_changed"]
        assert not (await command(root, "execute", done["result"]))["ok"]
        rollback = await request(root, finding, pending["record"]["candidate_id"])
        assert (
            rollback["record"]["approval"]["approval_id"]
            != pending["record"]["approval"]["approval_id"]
        )
        assert not (await command(root, "execute", rollback))["ok"]
        reviewed = await command(root, "approve", rollback)
        restored = await command(root, "execute", reviewed["result"])
        assert restored["ok"] and restored["result"]["status"] == "ROLLED_BACK"
        assert marker.read_bytes() == AVAILABLE
        assert not (await command(root, "execute", restored["result"]))["ok"]
        assert (await security_check(monitor.pipeline))["write_spy_calls"] == 0
        assert read_authentication_view(monitor.pipeline) == original_evidence
        assert original_evidence.inference_status == "NOT_INFERABLE"
        assert original_evidence.action_policy == "WRITE_DENIED"
        assert monitor.store.verify_audit()
        saved = server.restricted.records()
    restarted = LinuxMonitor(root)
    await restarted.run(duration_seconds=0.2, operator_uids=(os.geteuid(),))
    assert RestrictedResponseExecutor(restarted).records() == saved
    assert marker.read_bytes() == AVAILABLE
    assert restarted.pipeline.queue.counts() == {"DONE": 3}
    assert restarted.store.verify_audit()


@pytest.mark.asyncio
async def test_default_deny_and_no_implicit_test_resource(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    executor = RestrictedResponseExecutor(monitor)
    assert executor.settings()["response_mode"] == "DISABLED"
    assert not (root / "test-resources").exists()
    with pytest.raises(ExecutionDeniedError):
        executor.enable_test_mode(test_mode=False)
    monitor.store.update(state="RUNNING")
    with pytest.raises(ExecutionDeniedError):
        executor.enable_test_mode(test_mode=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "root-symlink",
        "marker-symlink",
        "root-replace",
        "marker-replace",
        "hardlink",
        "permissions",
        "content",
    ],
)
async def test_resource_isolation_and_replacement_denied(tmp_path, monkeypatch, attack):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, _):
        approval = await approved(root, finding)
        directory, marker = root / "test-resources", root / "test-resources/marker"
        outside = tmp_path / "outside"
        outside.mkdir(mode=0o700)
        external = outside / "marker"
        external.write_bytes(b"EXTERNAL_SENTINEL")
        if attack.startswith("root-"):
            directory.rename(root / "old-test-resources")
            if attack == "root-symlink":
                directory.symlink_to(outside, target_is_directory=True)
            else:
                directory.mkdir(mode=0o700)
                marker.write_bytes(AVAILABLE)
                marker.chmod(0o600)
        elif attack == "marker-symlink":
            marker.rename(directory / "old-marker")
            marker.symlink_to(external)
        elif attack == "marker-replace":
            marker.rename(directory / "old-marker")
            marker.write_bytes(AVAILABLE)
            marker.chmod(0o600)
        elif attack == "hardlink":
            os.link(marker, outside / "hardlink")
        elif attack == "permissions":
            directory.chmod(0o755)
        else:
            marker.write_bytes(b"EXTERNAL_CHANGE")
        assert not (await command(root, "execute", approval))["ok"]
        assert external.read_bytes() == b"EXTERNAL_SENTINEL"


@pytest.mark.asyncio
@pytest.mark.parametrize("resource_id", ["../marker", "/etc/passwd", "x/y", "other-resource"])
async def test_direct_path_and_unregistered_resource_contract_rejected(
    tmp_path, monkeypatch, resource_id
):
    from pydantic import ValidationError

    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, _):
        record = await request(root, finding)
        value = record["record"]["action"]["tool_input"]
        import json

        payload = json.loads(value)
        assert RestrictedInput.model_validate(payload).resource_id == "test-marker"
        payload["resource_id"] = resource_id
        with pytest.raises(ValidationError):
            RestrictedInput.model_validate(payload)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason", ["expired", "rejected", "policy", "evidence", "stopped", "snapshot"]
)
async def test_approval_context_revalidation_before_file_effect(tmp_path, monkeypatch, reason):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        pending = await request(root, finding)
        if reason == "rejected":
            decision = await command(root, "reject", pending)
        else:
            decision = await command(root, "approve", pending)
        assert decision["ok"]
        if reason == "expired":
            expiry = server.restricted.records()[0].approval.expires_at
            server.restricted.clock = lambda: expiry
        elif reason == "policy":

            class Changed(PolicyEngine):
                def evaluate(self, metadata):
                    return PolicyResult(decision=PolicyDecision.REQUIRE_APPROVAL, reason="changed")

            server.restricted.policy = Changed()
        elif reason == "evidence":
            with monitor.pipeline.store.database.transaction() as c:
                c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
        elif reason == "stopped":
            monitor.store.update(state="STOPPING")
        record = pending if reason == "snapshot" else decision["result"]
        assert not (await command(root, "execute", record))["ok"]
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["reservation", "receipt"])
async def test_audit_failure_is_not_reported_as_success(tmp_path, monkeypatch, boundary):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        approval = await approved(root, finding)
        original = monitor.store._audit

        def fault(c, kind, details):
            if kind == "RESTRICTED_RECORD" and details["record"]["status"] == (
                "STARTED" if boundary == "reservation" else "TEST_RESOURCE_CHANGED"
            ):
                raise OSError("TEST_AUDIT_FAILURE")
            return original(c, kind, details)

        monkeypatch.setattr(monitor.store, "_audit", fault)
        assert not (await command(root, "execute", approval))["ok"]
        record = server.restricted.records()[0]
        assert record.status == ("APPROVED" if boundary == "reservation" else "UNKNOWN")
        assert (root / "test-resources/marker").read_bytes() == (
            AVAILABLE if boundary == "reservation" else QUARANTINED
        )
        assert record.receipt is None


@pytest.mark.asyncio
async def test_concurrent_request_uses_one_effect_and_no_approval_replay(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, server):
        approval = await approved(root, finding)
        outcomes = await asyncio.gather(
            command(root, "execute", approval), command(root, "execute", approval)
        )
        assert sum(r["ok"] for r in outcomes) == 1
        assert len([r for r in server.restricted.records() if r.receipt]) == 1
        assert not (await command(root, "approve", approval))["ok"]


@pytest.mark.asyncio
async def test_rollback_conflict_is_not_overwritten(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, _):
        approval = await approved(root, finding)
        done = await command(root, "execute", approval)
        rollback = await request(root, finding, done["result"]["record"]["candidate_id"])
        reviewed = await command(root, "approve", rollback)
        marker = root / "test-resources/marker"
        marker.write_bytes(b"EXTERNAL_CONFLICT")
        assert not (await command(root, "execute", reviewed["result"]))["ok"]
        assert marker.read_bytes() == b"EXTERNAL_CONFLICT"


@pytest.mark.asyncio
async def test_handler_cannot_be_called_without_governed_dispatch(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, server):
        await approved(root, finding)
        record = server.restricted.records()[0]
        executor, _, _ = server.restricted._executor(record.action, record.approval)
        tool = executor._registry.get(record.action.tool_name)
        with pytest.raises(ExecutionDeniedError, match="GOVERNED_DISPATCH"):
            await tool.execute(record.action.input_payload())
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.asyncio
async def test_expiry_between_reservation_and_dispatch_denied(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        approval = await approved(root, finding)
        current = [server.restricted.clock()]
        server.restricted.clock = lambda: current[0]
        audit = monitor.store._audit

        def advance(c, kind, details):
            result = audit(c, kind, details)
            if kind == "RESTRICTED_RECORD" and details["record"]["status"] == "STARTED":
                current[0] += timedelta(hours=1)
            return result

        monkeypatch.setattr(monitor.store, "_audit", advance)
        assert not (await command(root, "execute", approval))["ok"]
        assert server.restricted.records()[0].status == "UNKNOWN"
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE
        assert not (await operator_request(root, "restricted-request", finding_id=finding))["ok"]


@pytest.mark.asyncio
async def test_completed_receipt_resource_conflict_blocks_recovery(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, server):
        result = await command(root, "execute", await approved(root, finding))
        assert result["ok"]
        marker = root / "test-resources/marker"
        marker.write_bytes(AVAILABLE)  # External conflicting restoration without approval.
        server.restricted.recover()
        assert not (await operator_request(root, "restricted-request", finding_id=finding))["ok"]
        with monitor.store.database.transaction(write=False) as c:
            assert any(
                e["kind"] == "RESTRICTED_RECOVERY_CONFLICT" for e in server.restricted._events(c)
            )
        assert marker.read_bytes() == AVAILABLE


@pytest.mark.asyncio
async def test_registered_resource_is_validated_before_first_action_on_restart(
    tmp_path, monkeypatch
):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    executor = RestrictedResponseExecutor(monitor)
    with exclusive_runtime_lock(root / "writer.lock"):
        executor.enable_test_mode(test_mode=True)
        (root / "test-resources/marker").write_bytes(QUARANTINED)
        executor.recover()
    assert executor.settings()["resource_health"] == "BLOCKED"
    with monitor.store.database.transaction(write=False) as c:
        assert any(e["kind"] == "RESTRICTED_RECOVERY_CONFLICT" for e in executor._events(c))


@pytest.mark.asyncio
async def test_runtime_root_clone_cannot_adopt_registered_identity(tmp_path, monkeypatch):
    import shutil

    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    executor = RestrictedResponseExecutor(monitor)
    with exclusive_runtime_lock(root / "writer.lock"):
        registration = executor.enable_test_mode(test_mode=True)
    old = tmp_path / "old-runtime"
    root.rename(old)
    shutil.copytree(old, root)
    from soc_agent.linux_runtime.restricted_resource import TestResource

    with pytest.raises(ValueError, match="REPLACED"):
        TestResource(root).probe(registration)
    assert (root / "test-resources/marker").read_bytes() == AVAILABLE
    assert (old / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["actor", "target", "incident", "unauthorized-peer"])
async def test_restricted_operator_wire_cannot_supply_authority(tmp_path, monkeypatch, attack):
    import json
    from uuid import uuid4

    from soc_agent.linux_runtime import operator
    from soc_agent.state.evidence import utc_now

    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, _):
        pending = await request(root, finding)
        if attack == "unauthorized-peer":
            monkeypatch.setattr(operator, "peer_uid", lambda sock: os.geteuid() + 1)
            reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
            assert not json.loads(await reader.readline())["ok"]
            writer.close()
            await writer.wait_closed()
        else:
            reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
            hello = json.loads(await reader.readline())
            value = operator.OperatorRequest(
                request_id=uuid4(),
                challenge=hello["challenge"],
                created_at=utc_now(),
                command="restricted-approve",
                candidate_id=pending["record"]["candidate_id"],
                expected_digest=pending["record_digest"],
            ).model_dump(mode="json")
            value[
                {"actor": "actor", "target": "resource_id", "incident": "incident_id"}[attack]
            ] = "forged"
            writer.write(json.dumps(value).encode() + b"\n")
            await writer.drain()
            assert not json.loads(await reader.readline())["ok"]
            writer.close()
            await writer.wait_closed()
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE
