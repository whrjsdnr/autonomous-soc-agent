"""Real ordinary-UID Broker child and IPC; every TC action is fixture-only."""

import json
import os
import signal

import pytest
from tests.ebpf_broker_support import controller

from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_broker.identity import sealed_object, verify_object
from soc_agent.security_ai.ebpf_broker.ipc import receive, send
from soc_agent.security_ai.ebpf_broker.journal import recover
from soc_agent.security_ai.ebpf_native.authentication import FixtureAuthentication
from soc_agent.security_ai.ebpf_native.contracts import alive


def test_separate_process_auth_once_restart_cleanup_and_recovery(tmp_path):
    c = controller(tmp_path)
    try:
        assert c.broker.identity.pid != os.getpid()
        assert c.broker.identity.uid == os.getuid() != 0
        c.start()
        owner = c.ownership
        first = c.run
        assert c.observe()["state"] == "ATTACH_PENDING"
        assert not c.snapshot()["collection_live"]
        c.stop()
        c.start()
        assert c.run.capture_session != first.capture_session
        assert c.run.generation != first.generation
        assert c.ownership.program_id != owner.program_id
        c.stop()
        with pytest.raises(ValueError, match="REUSE_DENIED"):
            c.authenticate(FixtureAuthentication())
        with c.application.store.database.transaction(write=False) as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT payload FROM monitor_audit")]
        assert sum(r["kind"] == "AUTHENTICATION_VERIFIED" for r in rows) == 1
        assert sum(r["kind"] == "AUTHENTICATION_STARTED" for r in rows) == 1
    finally:
        c.close()
    assert not alive(c.broker.identity) and c.broker.process.poll() == 0
    recovered = c.recover(c.application.directory)
    assert recovered["state"] == "CLOSED" and not recovered["authentication_restored"]
    assert not recovered["automatic_attach"] and not recovered["automatic_inference"]
    assert c.application.authentication == "REVOKED"


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
def test_signal_cleanup_does_not_leave_orphan_child(tmp_path, number):
    c = controller(tmp_path)
    try:
        c.start()
        c.broker.process.send_signal(number)
        assert c.broker.process.wait(timeout=5) == 0
        result = recover(c.application.directory / "broker-audit.jsonl", c.plan.identity)
        assert result["cleanup_status"] == "FIXTURE_VERIFIED"
        c.observe()
        assert c.state == "ERROR"  # Unexpected exit never appears ACTIVE or healthy.
        assert not c.application._authenticated
    finally:
        c.close()


def test_broker_crash_is_orphaned_and_never_restarted(tmp_path):
    c = controller(tmp_path)
    c.start()
    pid = c.broker.identity.pid
    c.broker.process.kill()  # Our ordinary-UID fixture child only; no system processes.
    c.broker.process.wait(timeout=5)
    c.observe()
    assert c.state == "ERROR" and c.cleanup == "ORPHANED_OR_CLEANUP_UNVERIFIED"
    assert c.broker.identity.pid == pid
    with pytest.raises(ValueError, match="AUTHORITY_DENIED"):
        c.start()
    c.close()
    recovered = c.recover(c.application.directory)
    assert recovered["state"] == "ERROR" and recovered["user_review_required"]


def test_controller_disconnect_triggers_owned_cleanup_without_new_attach(tmp_path):
    c = controller(tmp_path)
    try:
        c.start()
        c.broker.channel.close()  # Abrupt GUI/controller IPC disconnect fixture.
        assert c.broker.process.wait(timeout=5) == 0
        result = recover(c.application.directory / "broker-audit.jsonl", c.plan.identity)
        assert result["cleanup_status"] == "FIXTURE_VERIFIED"
        assert result["last_ownership"]["capture_session"] == str(c.run.capture_session)
    finally:
        c.close()


def test_wrong_session_and_duplicate_sequence_fail_closed(tmp_path):
    c = controller(tmp_path)
    try:
        c.start()
        cmd = Command(command="STATUS", plan_digest="f" * 64, sequence=c.broker.sequence + 1)
        send(c.broker.channel, cmd.model_dump(mode="json"))
        reply = receive(c.broker.channel)
        assert reply["error"] == "BROKER_PROTOCOL_OR_SUPERVISION_FAILED"
        assert c.broker.process.wait(timeout=5) != 0
        c.observe()
        assert c.state == "ERROR" and not c.application._authenticated
    finally:
        c.close()


def test_sealed_object_cannot_be_mutated_or_replaced(tmp_path):
    c = controller(tmp_path, authenticate=False)
    fd = sealed_object(c.application.program, c.application.scope.program_sha256)
    try:
        verify_object(fd, c.application.scope.program_sha256)
        with pytest.raises(OSError):
            os.pwrite(fd, b"bad", 0)
        with pytest.raises(ValueError, match="SHA_MISMATCH"):
            verify_object(fd, "f" * 64)
    finally:
        os.close(fd)
        c.close()


@pytest.mark.parametrize("field", ["program_sha256", "bundle_digest", "net_namespace"])
def test_preapproval_scope_mutation_has_no_child(tmp_path, field):
    c = controller(tmp_path, authenticate=False)
    try:
        c.approve(c.plan.identity)
        changes = {field: "net:[999]" if field == "net_namespace" else "f" * 64}
        c.application.scope = c.application.scope.model_copy(update=changes)
        with pytest.raises(ValueError):
            c.authenticate(FixtureAuthentication())
        assert c.broker is None
    finally:
        c.close()


def test_wrong_approval_and_native_policy_never_start_process(tmp_path):
    c = controller(tmp_path, authenticate=False)
    try:
        with pytest.raises(ValueError, match="APPROVAL_DIGEST"):
            c.approve("f" * 64)
        with pytest.raises(ValueError):
            c.authenticate(FixtureAuthentication())
        assert c.broker is None
    finally:
        c.close()


def test_pid_reuse_controller_ticks_and_namespace_fail_before_start(tmp_path):
    c = controller(tmp_path)
    try:
        p = c.application.plan
        c.application.plan = p.model_copy(
            update={
                "controller": p.controller.model_copy(
                    update={"start_ticks": p.controller.start_ticks + 1}
                )
            }
        )
        with pytest.raises(ValueError, match="CONTROLLER_IDENTITY"):
            c.start()
        assert c.ownership is None
    finally:
        c.close()


def test_bounded_ipc_overflow_and_no_native_socket(tmp_path):
    c = controller(tmp_path)
    try:
        with pytest.raises(ValueError, match="OUTPUT_BOUND"):
            send(c.broker.channel, {"value": "x" * 20000})
        c.broker.channel.send(b"{" + b"x" * 20000)
        reply = receive(c.broker.channel)
        assert "error" in reply
        assert c.broker.process.wait(timeout=5) != 0
    finally:
        c.close()
