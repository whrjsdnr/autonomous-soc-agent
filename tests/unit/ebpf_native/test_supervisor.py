import pytest
from tests.ebpf_native_support import authenticated


def test_foreign_qdisc_and_filter_preservation(tmp_path):
    c = authenticated(tmp_path)
    qdisc = c.tc.qdisc
    for i in range(3):
        c.start(c.scope, now=i + 1)
        c.stop()
        assert c.tc.qdisc == qdisc and c.tc.filters == {(1, 1): "FOREIGN_FILTER"}


def test_unknown_ownership_never_deletes_foreign_filter_or_retries(tmp_path):
    c = authenticated(tmp_path)
    c.start(c.scope, now=1)
    lease = c.attachment
    key = (lease.priority, lease.handle)
    c.tc.filters[key] = "REPLACED_BY_FOREIGN_FIXTURE"
    with pytest.raises(ValueError, match="CLEANUP_UNVERIFIED"):
        c.close()
    assert c.tc.filters[key] == "REPLACED_BY_FOREIGN_FIXTURE"
    assert c.attachment == lease and not c._authenticated
    with pytest.raises(ValueError):
        c.start(c.scope, now=2)


@pytest.mark.parametrize("case", ["queue", "rss", "cpu", "nan", "crash", "controller", "timeout"])
def test_resource_crash_deadline_failures(tmp_path, monkeypatch, case):
    c = authenticated(tmp_path)
    c.start(c.scope, now=1)
    args = dict(now=2)
    if case == "queue":
        args["queue_depth"] = 33
    if case == "rss":
        args["rss_mib"] = 129
    if case == "cpu":
        args["cpu_seconds"] = 301
    if case == "nan":
        args["rss_mib"] = float("nan")
    if case == "crash":
        args["loader_alive"] = False
    if case == "controller":
        monkeypatch.setattr("soc_agent.security_ai.ebpf_native.application.alive", lambda _: False)
    if case == "timeout":
        result = c.observe(now=301)
        assert result["state"] == "CLOSED" and c.attachment is None
        return
    with pytest.raises(ValueError):
        c.observe(**args)
    assert c.state == "ERROR" and not c._authenticated
    assert c.attachment is not None
    c.stop()
    assert c.state == "ERROR" and c.attachment is None


def test_application_expiry_run_limit_and_idempotent_stop(tmp_path):
    c = authenticated(tmp_path / "expiry")
    with pytest.raises(ValueError, match="SESSION_EXPIRED"):
        c.start(c.scope, now=3600)
    b = authenticated(tmp_path / "runs")
    for i in range(16):
        b.start(b.scope, now=i + 1)
        b.stop()
    audit = b.store.verify_audit()
    b.stop()
    assert b.store.verify_audit() == audit
    with pytest.raises(ValueError, match="RUN_BUDGET"):
        b.start(b.scope, now=17)


def test_loader_pid_reuse_and_exclusive_attach_failure(tmp_path):
    c = authenticated(tmp_path / "loader")
    c.start(c.scope, now=1)
    wrong = c.loader_identity.model_copy(update={"start_ticks": c.loader_identity.start_ticks + 1})
    with pytest.raises(ValueError, match="LOADER_CRASH"):
        c.observe(now=2, loader_identity=wrong)
    c.stop()
    b = authenticated(tmp_path / "attach")

    def fail(*args):
        raise ValueError("FIXTURE_ATTACH_FAILED")

    b.tc.attach = fail
    with pytest.raises(ValueError, match="FIXTURE_ATTACH_FAILED"):
        b.start(b.scope, now=1)
    assert b.attachment is None and b.tc.filters == {(1, 1): "FOREIGN_FILTER"}


def test_application_expiry_ends_last_run_without_extending_grant(tmp_path):
    c = authenticated(tmp_path)
    c.start(c.scope, now=3599)
    with pytest.raises(ValueError, match="APPLICATION_SESSION_EXPIRED"):
        c.observe(now=3600)
    assert c.attachment is None and c.authentication == "REVOKED"
    assert c.tc.filters == {(1, 1): "FOREIGN_FILTER"}
