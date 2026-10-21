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
