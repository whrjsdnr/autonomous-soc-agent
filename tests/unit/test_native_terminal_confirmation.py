"""Human scope confirmation only; no OS authentication or Kernel action."""

from unittest.mock import Mock

import pytest

from soc_agent.security_ai.native_terminal import confirm_scope


def handoff():
    h = Mock()
    h.approval = "a" * 64
    h.approval_scope.return_value = {
        "session_id": "new-session",
        "program_sha256": "b" * 64,
        "interface": "lo",
        "hook": "INGRESS",
        "approval_digest": h.approval,
    }
    return h


def test_yes_binds_exact_displayed_digest_without_authentication():
    h = handoff()
    shown = []
    assert confirm_scope(h, lambda _: "yes", shown.append)
    assert '"interface": "lo"' in shown[0]
    h.approve.assert_called_once_with("a" * 64)
    h.authenticate_native.assert_not_called()


@pytest.mark.parametrize("answer", ["", "no", "a" * 64])
def test_default_and_digest_input_do_not_approve(answer):
    h = handoff()
    assert not confirm_scope(h, lambda _: answer, lambda _: None)
    h.approve.assert_not_called()
    h.authenticate_native.assert_not_called()


def test_scope_change_during_confirmation_is_rejected():
    h = handoff()

    def changed(_):
        h.approval_scope.return_value = {"interface": "eth0"}
        return "yes"

    with pytest.raises(ValueError, match="TERMINAL_APPROVAL_SCOPE_CHANGED"):
        confirm_scope(h, changed, lambda _: None)
    h.approve.assert_not_called()


def test_cancel_does_not_authenticate():
    h = handoff()

    def cancelled(_):
        raise KeyboardInterrupt

    assert not confirm_scope(h, cancelled, lambda _: None)
    h.approve.assert_not_called()
    h.authenticate_native.assert_not_called()
