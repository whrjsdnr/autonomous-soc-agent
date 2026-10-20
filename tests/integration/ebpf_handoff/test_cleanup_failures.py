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
