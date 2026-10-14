"""Additional v1 boundaries: kernel identity, runtime binding and offline setup failure."""

import os
import socket
import struct
from datetime import timedelta

import pytest
from tests.integration.linux_runtime.test_monitor import setup
from tests.integration.restricted_response.test_executor import approved, command, endpoint

from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.linux_runtime.restricted_models import RestrictedRecord
from soc_agent.linux_runtime.restricted_resource import AVAILABLE
from soc_agent.linux_runtime.restricted_response import (
    RestrictedResponseExecutor,
    authenticated_uid,
)
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.policy import PolicyDecision, PolicyResult
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.state.evidence import utc_now


@pytest.mark.parametrize("kind", ["fake", "subclass", "datagram", "inet"])
def test_kernel_identity_cannot_be_replaced_by_an_actor_or_socket_facade(kind):
    class FakePeer:
        family = socket.AF_UNIX

        def getsockopt(self, *_):
            return struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())

    class ForgedSocket(socket.socket):
        def getsockopt(self, *_):
            return struct.pack("3i", os.getpid(), os.geteuid(), os.getegid())

    peer = (
        FakePeer()
        if kind == "fake"
        else ForgedSocket(socket.AF_UNIX)
        if kind == "subclass"
        else socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if kind == "datagram"
        else socket.socket(socket.AF_INET)
    )
    try:
        with pytest.raises(ExecutionDeniedError):
            authenticated_uid(peer)
    finally:
        if isinstance(peer, socket.socket):
            peer.close()


@pytest.mark.asyncio
async def test_runtime_config_change_invalidates_exact_approval(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, monitor, finding, _, _):
        action = await approved(root, finding)
        monitor.config = monitor.config.model_copy(update={"max_tool_calls": 1})
        result = await command(root, "execute", action)
        assert not result["ok"]
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["quarantine", "rollback"])
@pytest.mark.parametrize("failure", ["denied", "partial"])
async def test_tool_write_failure_is_unknown_and_is_not_replayed(
    tmp_path, monkeypatch, operation, failure
):
    from tests.integration.restricted_response.test_executor import request

    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, server):
        action = await approved(root, finding)
        if operation == "rollback":
            done = await command(root, "execute", action)
            pending = await request(root, finding, done["result"]["record"]["candidate_id"])
            action = (await command(root, "approve", pending))["result"]
        marker = root / "test-resources/marker"
        before = marker.read_bytes()

        write = os.pwrite

        def denied(fd, value, offset):
            if failure == "denied":
                raise PermissionError("Fixture write denied")
            write(fd, b"BROKEN", offset)
            return 1

        monkeypatch.setattr(os, "pwrite", denied)
        result = await command(root, "execute", action)
        assert not result["ok"] and result["status"] == "UNKNOWN"
        saved = next(
            r
            for r in server.restricted.records()
            if r.candidate_id == action["record"]["candidate_id"]
        )
        assert saved.status == "UNKNOWN" and saved.receipt is None
        assert saved.recovery_observation == ("UNCHANGED" if failure == "denied" else "UNAVAILABLE")
        observed = marker.read_bytes()
        assert observed == before if failure == "denied" else observed.startswith(b"BROKEN")
        assert not (
            await command(
                root,
                "execute",
                {"record": saved.model_dump(mode="json"), "record_digest": saved.digest},
            )
        )["ok"]
        assert marker.read_bytes() == observed


@pytest.mark.asyncio
async def test_expiry_while_opening_marker_is_revalidated_before_write(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, server):
        now = [utc_now()]
        server.restricted.clock = lambda: now[0]
        action = await approved(root, finding)
        change = server.restricted.resource.change

        def delayed(*args, **kwargs):
            now[0] += timedelta(days=1)
            return change(*args, **kwargs)

        monkeypatch.setattr(server.restricted.resource, "change", delayed)
        result = await command(root, "execute", action)
        assert not result["ok"] and result["status"] == "UNKNOWN"
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE


@pytest.mark.asyncio
async def test_receipt_contains_exact_authenticated_operator(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, _):
        action = await approved(root, finding)
        result = await command(root, "execute", action)
        assert result["ok"]
        done = RestrictedRecord.model_validate(result["result"]["record"])
        assert done.receipt.operator_uid == os.geteuid()
        assert done.approval.decision.decided_by == f"os-uid:{os.geteuid()}"


@pytest.mark.asyncio
async def test_allow_policy_cannot_eliminate_explicit_human_approval(tmp_path, monkeypatch):
    async with endpoint(tmp_path, monkeypatch) as (root, _, finding, _, server):
        action = await approved(root, finding)
        monkeypatch.setattr(
            server.restricted.policy,
            "evaluate",
            lambda _: PolicyResult(decision=PolicyDecision.ALLOW, reason="Changed policy"),
        )
        result = await command(root, "execute", action)
        assert not result["ok"]
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE


def test_failed_registration_audit_leaves_an_unregistered_resource_denied(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    executor = RestrictedResponseExecutor(monitor)
    before = monitor.store.verify_audit()
    audit = monitor.store._audit

    def fail(connection, kind, details):
        if kind == "RESTRICTED_TEST_MODE":
            raise OSError("Injected audit failure")
        return audit(connection, kind, details)

    with exclusive_runtime_lock(root / "writer.lock"):
        monkeypatch.setattr(monitor.store, "_audit", fail)
        with pytest.raises(OSError):
            executor.enable_test_mode(test_mode=True)
        monkeypatch.setattr(monitor.store, "_audit", audit)
        executor.recover()
        assert executor.settings()["response_mode"] == "DISABLED"
        assert monitor.store.verify_audit() == before
        assert (root / "test-resources/marker").read_bytes() == AVAILABLE
        with pytest.raises(FileExistsError):
            executor.enable_test_mode(test_mode=True)


@pytest.mark.asyncio
async def test_restart_cannot_adopt_registered_root_renamed_behind_a_symlink(tmp_path, monkeypatch):
    from tests.integration.restricted_response.test_executor import prepare

    root, _, _, registration = await prepare(tmp_path, monkeypatch)
    relocated = tmp_path / "relocated-runtime"
    root.rename(relocated)
    root.symlink_to(relocated, target_is_directory=True)
    restarted = LinuxMonitor(root)
    executor = RestrictedResponseExecutor(restarted)
    with pytest.raises(ValueError, match="REPLACED"):
        executor.resource.probe(registration)
    executor.recover()
    assert executor.settings()["resource_health"] == "BLOCKED"
    assert (relocated / "test-resources/marker").read_bytes() == AVAILABLE
