"""Application password once, per-run identity and strict Native prohibition."""

import json

import pytest
from tests.ebpf_native_support import application, authenticated

from soc_agent.security_ai.ebpf_native.application import Application
from soc_agent.security_ai.ebpf_native.authentication import (
    FixtureAuthentication,
    native_authenticate,
)
from soc_agent.security_ai.ebpf_native.loader import native_load_or_attach


def events(c):
    with c.store.database.transaction(write=False) as db:
        return [
            json.loads(r[0])
            for r in db.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
        ]


def test_password_once_same_application_start_stop_restart_and_close(tmp_path):
    c = authenticated(tmp_path)
    c.start(c.scope, now=1)
    first = c.run
    assert c.state == "ATTACH_PENDING" and not c.snapshot()["collection_live"]
    c.stop()
    c.start(c.scope, now=2)
    assert first.capture_session != c.run.capture_session and first.generation != c.run.generation
    assert first.application_session == c.run.application_session
    assert sum(r["kind"] == "AUTHENTICATION_STARTED" for r in events(c)) == 1
    assert sum(r["kind"] == "AUTHENTICATION_VERIFIED" for r in events(c)) == 1
    with pytest.raises(ValueError, match="ORDER_DENIED"):
        c.authenticate(FixtureAuthentication(), now=3)
    c.close()
    assert c.authentication == "REVOKED"
    with pytest.raises(ValueError):
        c.start(c.scope, now=4)
    assert c.tc.filters == {(1, 1): "FOREIGN_FILTER"}


@pytest.mark.parametrize(
    "change,code",
    [
        ({"tty": False}, "TTY_REQUIRED"),
        ({"cached_only": True}, "FRESH_APPLICATION_PASSWORD"),
        ({"nopasswd": True}, "PASSWORD_POLICY_UNVERIFIED"),
        ({"policy_password_guaranteed": False}, "PASSWORD_POLICY_UNVERIFIED"),
        ({"password_challenge_completed": False}, "FRESH_APPLICATION_PASSWORD"),
        ({"result": "CANCELLED"}, "CANCELLED"),
        ({"result": "TIMEOUT"}, "TIMEOUT"),
        ({"result": "DENIED"}, "DENIED"),
    ],
)
def test_cached_nopasswd_cancel_timeout_no_retry(tmp_path, change, code):
    c = application(tmp_path)
    c.prepare()
    c.approve(c.plan.identity)
    with pytest.raises(ValueError, match=code):
        c.authenticate(FixtureAuthentication.model_validate(change), now=0)
    assert c.state == "ERROR" and c.authentication == "FAILED"
    assert not any(r["kind"] == "AUTHENTICATION_VERIFIED" for r in events(c))
    with pytest.raises(ValueError):
        c.authenticate(FixtureAuthentication(), now=1)
    assert c.tc.filters == {(1, 1): "FOREIGN_FILTER"}


def test_new_application_requires_new_approval_and_password(tmp_path):
    a = authenticated(tmp_path / "one")
    a.close()
    b = application(tmp_path / "two")
    b.prepare()
    assert a.plan.application_session != b.plan.application_session
    with pytest.raises(ValueError, match="APPROVAL_DIGEST"):
        b.approve(a.plan.identity)
    assert b.authentication == "REQUIRED"


def test_scope_change_explicit_approval_without_second_password(tmp_path):
    c = authenticated(tmp_path)
    other = c.scope.model_copy(update={"hook": "EGRESS"})
    with pytest.raises(ValueError, match="SCOPE_CHANGE"):
        c.start(other, now=1)
    token = c.scope_approval_digest(other)
    with pytest.raises(ValueError, match="SCOPE_APPROVAL_DIGEST"):
        c.approve_scope(other, "f" * 64)
    c.approve_scope(other, token)
    c.start(other, now=2)
    c.stop()
    assert sum(r["kind"] == "AUTHENTICATION_STARTED" for r in events(c)) == 1
    assert any(r["kind"] == "SCOPE_APPROVAL_ACCEPTED" for r in events(c))
    with pytest.raises(ValueError, match="SCOPE_APPROVAL_NO_CHANGE"):
        c.approve_scope(other, token)


@pytest.mark.parametrize(
    "field,code",
    [
        ("program_sha256", "PROGRAM_SHA"),
        ("loader_sha256", "LOADER_SHA"),
        ("bundle_digest", "BUNDLE_MISMATCH"),
        ("net_namespace", "NAMESPACE"),
        ("ifindex", "INTERFACE_IDENTITY"),
    ],
)
def test_identity_failures_never_authenticate(tmp_path, field, code):
    changes = {
        field: (
            "net:[999999]" if field == "net_namespace" else 9999 if field == "ifindex" else "f" * 64
        )
    }
    c = application(tmp_path, **changes)
    with pytest.raises(ValueError, match=code):
        c.prepare()
    assert not c._authenticated and c.state == "ERROR"


def test_post_auth_program_mutation_controller_pid_reuse(tmp_path):
    c = authenticated(tmp_path / "file")
    c.program.write_bytes(c.program.read_bytes() + b"x")
    with pytest.raises(ValueError, match="PROGRAM_SHA"):
        c.start(c.scope, now=1)
    b = authenticated(tmp_path / "pid")
    wrong = b.plan.controller.model_copy(update={"start_ticks": b.plan.controller.start_ticks + 1})
    b.plan = b.plan.model_copy(update={"controller": wrong})
    with pytest.raises(ValueError, match="CONTROLLER_IDENTITY"):
        b.start(b.scope, now=1)


def test_recovery_verifies_audit_but_never_restores_auth_authority(tmp_path):
    c = authenticated(tmp_path)
    c.start(c.scope, now=1)
    c.stop()
    audit = c.store.verify_audit()
    restored = Application.recover(c.directory)
    assert restored["runtime_audit_integrity"] == audit and not restored["authentication_restored"]
    assert not restored["approval_restored"] and not restored["automatic_attach"]
    assert restored["authentication"] == "REQUIRED_NEW_APPLICATION"
    text = json.dumps(events(c))
    assert "password_challenge_completed" not in text and "_authenticated" not in text
    assert "sudo_token" not in text
    with c.store.database.transaction() as db:
        db.execute("UPDATE monitor_audit SET digest=? WHERE sequence=2", ("f" * 64,))
    with pytest.raises(ValueError):
        Application.recover(c.directory)


def test_native_adapters_and_kernel_active_are_unreachable(tmp_path):
    with pytest.raises(ValueError, match="DISABLED"):
        native_authenticate()
    with pytest.raises(ValueError, match="DISABLED"):
        native_load_or_attach()
    c = application(tmp_path)
    c.plan = c.plan.model_copy(update={"mode": "PHASE_A_NATIVE_BLOCKED"})
    c.prepare()
    c.approve(c.plan.identity)
    with pytest.raises(ValueError, match="NATIVE_AUTHENTICATION_PENDING"):
        c.authenticate(FixtureAuthentication(), now=0)
    assert not c._authenticated and c.snapshot()["native_ai"] == "BLOCKED"


def test_authentication_audit_failure_revokes_authority_without_retry(tmp_path, monkeypatch):
    c = authenticated(tmp_path)

    def fail(*args, **kwargs):
        raise ValueError("SIMULATED_AUDIT_FAILURE")

    monkeypatch.setattr(c.store, "event", fail)
    with pytest.raises(ValueError, match="AUDIT_FAILED"):
        c.start(c.scope, now=1)
    assert c.state == "ERROR" and not c._authenticated and c.attachment is None
    with pytest.raises(ValueError):
        c.start(c.scope, now=2)


def test_gui_never_inherits_privilege_even_for_same_uid(tmp_path, monkeypatch):
    c = application(tmp_path)
    monkeypatch.setattr(
        "soc_agent.security_ai.ebpf_native.application.controller_unprivileged", lambda: False
    )
    with pytest.raises(ValueError, match="NON_ROOT_CONTROLLER"):
        c.prepare()
    assert c.state == "ERROR" and not c._authenticated


def test_scope_digest_replay_after_returning_to_previous_hook_is_denied(tmp_path):
    c = authenticated(tmp_path)
    original = c.scope
    other = original.model_copy(update={"hook": "EGRESS"})
    old = c.scope_approval_digest(other)
    c.approve_scope(other, old)
    c.approve_scope(original, c.scope_approval_digest(original))
    with pytest.raises(ValueError, match="SCOPE_APPROVAL_DIGEST"):
        c.approve_scope(other, old)
    c.approve_scope(other, c.scope_approval_digest(other))
    assert sum(r["kind"] == "AUTHENTICATION_STARTED" for r in events(c)) == 1


def test_application_audit_budget_prevents_unbounded_diagnostics(tmp_path):
    c = authenticated(tmp_path)
    c._event_count = c.scope.max_audit_events
    with pytest.raises(ValueError, match="AUDIT_BUDGET"):
        c.start(c.scope, now=1)
    assert not c._authenticated and c.authentication == "REVOKED"


def test_recovery_of_unclosed_run_never_claims_cleanup_or_reattaches(tmp_path):
    c = authenticated(tmp_path)
    c.start(c.scope, now=1)
    value = Application.recover(c.directory)
    assert value["state"] == "ERROR" and value["cleanup_status"] == "UNVERIFIED_RECOVERY_PENDING"
    assert not value["authentication_restored"] and not value["automatic_attach"]
    assert c.attachment is not None
    c.close()
