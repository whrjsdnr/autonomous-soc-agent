"""Authority must be revoked even if the journal or audit writer fails."""

import pytest

from soc_agent.security_ai.ebpf_tc.os_handoff import AuthenticationFixture


@pytest.mark.parametrize("mutation", ["deleted", "corrupt"])
def test_cleanup_journal_failure_cannot_leave_authenticated_display(session, mutation):
    h, _ = session
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture())
    if mutation == "deleted":
        h.audit_path.unlink()
    else:
        with h.audit_path.open("r+b") as stream:
            stream.write(b"invalid")
    result = h.close()
    assert result["os_authentication"] == "REVOKED"
    assert result["cleanup_status"] == "CLEANUP_UNVERIFIED"
    assert result["state"] in {"ERROR", "CLEANUP_UNVERIFIED"}
    assert h.ended and h.deadline is None and h.child.poll() == 0


def test_audit_write_failure_still_closes_owned_connection(session, monkeypatch):
    h, _ = session
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture())

    def failed_event(*args, **kwargs):
        raise OSError("fixture audit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(h, "_event", failed_event)
        with pytest.raises(OSError):
            h._reject("HANDOFF_AUDIT_FAILURE")
    assert h.ended and h.channel is None and h.authentication == "REVOKED"
    assert h.child.poll() is not None


def test_control_receive_errno_and_original_api_survive_session_revocation(session, monkeypatch):
    from soc_agent.security_ai.ebpf_broker.contracts import Command

    h, _ = session
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture())

    def failed_receive(**_):
        raise OSError(104, "private peer address must not enter audit")

    monkeypatch.setattr(h, "_next", failed_receive)
    with pytest.raises(OSError):
        h.command(Command(command="STATUS", plan_digest=h.plan.approval, sequence=1))
    detail = h.snapshot()["control_failures"][0]
    assert detail["stage"] == "COMMAND_RECEIVE" and detail["errno"] == 104
    assert detail["api"] == "Handoff._next/socket.recvmsg"
    assert detail["command"] == "STATUS" and detail["request_sequence"] == 1
    assert "private peer" not in str(detail)
    assert h.ended and h.channel is None and h.authentication == "REVOKED"
    assert h.application.store.verify_audit()


def test_concurrent_heartbeat_and_gui_status_use_one_request_sequence(session):
    from concurrent.futures import ThreadPoolExecutor

    h, _ = session
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture())
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(h.observe) for _ in range(6)]
        for future in futures:
            assert future.result(5)["last_error"] is None
    assert h.sequence == 6 and not h.ended
    assert h.close()["cleanup_status"] == "FIXTURE_VERIFIED"


def test_processing_error_does_not_turn_valid_status_or_stop_into_control_failure(session):
    from soc_agent.security_ai.ebpf_broker.contracts import Command
    from soc_agent.security_ai.ebpf_native.contracts import RunIdentity
    from soc_agent.security_ai.research.models import digest

    h, _ = session
    h.approve(h.approval)
    # Select the real ordinary-UID data-channel peer. No PREPARE is sent, so
    # this placeholder record is never decoded or forwarded as a packet.
    h.authenticate_fixture(AuthenticationFixture(), packets=(bytes(80),))
    assert h.data.worker is not None
    h.data.error = "EBPF_REORDER_LATE_CAPTURE_GAP"
    # Reproduce the Native COMMAND_DATA_PUMP failure without Kernel activity.
    with pytest.raises(ValueError, match="EBPF_REORDER_LATE_CAPTURE_GAP"):
        h.data.pump()
    h.command(Command(command="STATUS", plan_digest=h.plan.approval, sequence=1))
    assert not h.ended and h.state == "BROKER_READY" and h.error is None
    run = RunIdentity(
        application_session=h.plan.broker.application.application_session,
        scope_digest=digest(h.plan.broker.application.scope.model_dump(mode="json")),
        run_number=1,
    )
    for command in ("PREPARE", "ATTACH"):
        with pytest.raises(ValueError, match="HANDOFF_NEW_WORK_AFTER_DATA_FAILURE"):
            h.command(
                Command(
                    command=command,
                    plan_digest=h.plan.approval,
                    sequence=2,
                    run=run if command == "ATTACH" else None,
                )
            )
        assert h.sequence == 1 and not h.ended
    h.stop()  # Same control session remains usable for owned cleanup / DNS drain.
    assert not h.ended and h.sequence == 2 and h.data.error == "EBPF_REORDER_LATE_CAPTURE_GAP"
    assert h.control_failures == []
    result = h.close()
    assert h.ended and h.authentication == "REVOKED"
    assert result["data_plane"]["error"] == "EBPF_REORDER_LATE_CAPTURE_GAP"
    assert result["cleanup_status"] == "CLEANUP_UNVERIFIED"  # Never hide the data failure.


def test_broken_data_transport_still_revokes_control_session(session):
    from soc_agent.security_ai.ebpf_broker.contracts import Command

    h, _ = session
    h.approve(h.approval)
    h.authenticate_fixture(AuthenticationFixture(), packets=(bytes(80),))
    h.data.error = "TCX_DATA_EOF_WITHOUT_CLOSED"
    h.data.transport_failed = True
    with pytest.raises(ValueError, match="HANDOFF_DATA_INTEGRITY_FAILED"):
        h.command(Command(command="STATUS", plan_digest=h.plan.approval, sequence=1))
    assert h.ended and h.authentication == "REVOKED"
    assert h.control_failures[0]["stage"] == "COMMAND_RECEIVE"
    assert h.data.error == "TCX_DATA_EOF_WITHOUT_CLOSED"


def test_ebpf_symbolic_root_error_is_retained_but_unstructured_text_is_redacted():
    from soc_agent.security_ai.collectors.handoff import failure_evidence

    original = failure_evidence(
        ValueError("EBPF_REORDER_LATE_CAPTURE_GAP"),
        stage="TCX_DATA_PROCESSING",
        api="PacketChannel.error",
    )
    assert original["original_code"] == "EBPF_REORDER_LATE_CAPTURE_GAP"
    assert original["errno"] is None and not original["message_redacted"]
    secret = failure_evidence(ValueError("EBPF_PRIVATE password=hidden"), stage="TEST", api="TEST")
    assert secret["original_code"] is None and secret["message_redacted"]
    assert "hidden" not in str(secret)
