"""Installed review lifecycle; no actual privilege, network or authorization."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from soc_agent import agent_release as release
from soc_agent import agent_runtime
from soc_agent.security_ai.research.models import digest


def put(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    release.save(path, value)


@pytest.fixture
def registered(tmp_path, monkeypatch):
    template = tmp_path / ".git" / "release" / "native"
    template.mkdir(mode=0o700, parents=True)
    for name in (
        "approval-request-final-v2.json",
        "scope-input.json",
        "runtime-config.json",
        "controller-python-binding.json",
        "execution/terminal.py",
    ):
        put(template / name, {"fixture": name})
    put(
        template / "execution/execution-pins.json",
        {
            str(template / "execution/terminal.py"): agent_runtime.sha(
                template / "execution/terminal.py"
            )
        },
    )
    monkeypatch.setattr(
        release,
        "verify_review",
        lambda *_a, **_k: {
            "code_identity": "a" * 64,
            "git_commit": "b" * 40,
            "files": {},
        },
    )
    home = tmp_path / "application"
    release.register(home, template)
    return home, template


def test_registration_is_not_authority_and_rejects_implicit_update(registered):
    home, template = registered
    fixed = release.installed(home)
    assert fixed["execution_authority"] is False
    assert not (home / "agent.json").exists()
    with pytest.raises(ValueError, match="EXPLICIT_UPDATE"):
        release.register(home, template)
    assert not list(template.rglob("*decision*"))


@pytest.mark.parametrize(
    "name", ["execution/terminal.py", "scope-input.json", "runtime-config.json"]
)
def test_release_tamper_blocks_before_session_or_process(registered, name):
    home, template = registered
    (template / name).write_text("changed")
    with pytest.raises(ValueError, match="RELEASE_CHANGED"):
        release.prepare(home)
    assert not list(template.parent.parent.glob("operator-session-*"))
    assert not (home / "agent.json").exists()


def test_reference_digest_tamper_rejected(registered):
    home, _ = registered
    path = home / "installed-release.json"
    document = json.loads(path.read_text())
    document["release"]["execution_authority"] = True
    document["digest"] = digest(document["release"])
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="RELEASE_INTEGRITY"):
        release.installed(home)


def session(tmp_path, monkeypatch, *, consumed=False):
    home = tmp_path / "app"
    execution = home / "review/execution"
    execution.mkdir(mode=0o700, parents=True)
    put(home / "agent.json", {"fixture": "No actual profile or authority"})
    put(
        execution.parent / "approval-request-final-v2.json",
        {"expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
    )
    monkeypatch.setattr(release, "profile", lambda _: SimpleNamespace(review=execution.parent))
    current = dict(
        state="STOPPED",
        cleanup="VERIFIED",
        collector_cleanup="VERIFIED",
        dns_transport=dict(cleanup="VERIFIED", transport_final_counter_verified=True),
    )
    monkeypatch.setattr(agent_runtime, "status", lambda _: current)
    if consumed:
        put(execution / "scope-confirmed.json", {"fixture": True})
        put(
            execution / "root-finished.json",
            {
                "primary_error": None,
                "socket_exists": False,
                "cleanup": [{"returncode": 0}],
            },
        )
        put(execution / "operator-terminal-result.json", {"returncode": 0})
        for unit in (
            "soc-continuous-collector",
            "soc-continuous-dns",
            "soc-continuous-dnsmasq",
            "soc-continuous-tcp-trial",
            "soc-operations-runtime",
        ):
            put(
                execution / (unit + ".service-final.json"),
                {"ActiveState": "inactive", "MainPID": "0"},
            )
        for name in ("namespace-after.json", "namespace-after-tcx.json"):
            put(execution / name, {"returncode": 0, "stdout": '[{"tc":[]}]'})
    return home, execution, current


def test_unused_session_and_expired_draft_have_no_execution_permission(tmp_path, monkeypatch):
    home, execution, _ = session(tmp_path, monkeypatch)
    assert release.prior_session(home) == "PREPARED"
    path = execution.parent / "approval-request-final-v2.json"
    path.write_text(json.dumps({"expires_at": "2020-01-01T00:00:00+00:00"}))
    assert release.prior_session(home) == "EXPIRED_UNUSED"
    assert not (execution / "scope-confirmed.json").exists()


@pytest.mark.parametrize("state", ["RUNNING", "DEGRADED", "STOPPING"])
def test_running_duplicate_block(tmp_path, monkeypatch, state):
    home, _, current = session(tmp_path, monkeypatch)
    current["state"] = state
    with pytest.raises(ValueError, match="ALREADY_RUNNING"):
        release.prior_session(home)


@pytest.mark.parametrize(
    "failure",
    [
        "first",
        "socket",
        "cleanup",
        "terminal",
        "runtime",
        "counter",
        "service",
        "namespace",
        "missing",
    ],
)
def test_previous_failure_cannot_be_automatic_native_retry(tmp_path, monkeypatch, failure):
    home, execution, current = session(tmp_path, monkeypatch, consumed=True)
    if failure in {"first", "socket", "cleanup"}:
        path = execution / "root-finished.json"
        value = json.loads(path.read_text())
        if failure == "first":
            value["primary_error"] = "FIRST_ERROR_RETAINED"
        elif failure == "socket":
            value["socket_exists"] = True
        else:
            value["cleanup"][0]["returncode"] = 7
        path.write_text(json.dumps(value))
    elif failure == "terminal":
        (execution / "operator-terminal-result.json").write_text('{"returncode":7}')
    elif failure == "runtime":
        current["cleanup"] = "UNVERIFIED"
    elif failure == "counter":
        current["dns_transport"]["transport_final_counter_verified"] = False
    elif failure == "service":
        (execution / "soc-continuous-dns.service-final.json").write_text(
            '{"ActiveState":"active","MainPID":"123"}'
        )
    elif failure == "namespace":
        (execution / "namespace-after.json").write_text('{"returncode":7}')
    else:
        (execution / "operator-terminal-result.json").unlink()
    with pytest.raises((ValueError, OSError)):
        release.prior_session(home)


def test_successful_cleanup_is_required_independently_of_exit_zero(tmp_path, monkeypatch):
    home, _, _ = session(tmp_path, monkeypatch, consumed=True)
    assert release.prior_session(home) == "CLOSED"


def test_no_profile_is_no_session(tmp_path):
    assert release.prior_session(tmp_path) == "ABSENT"


def test_register_cli_composes_existing_preparer_without_execution(tmp_path, monkeypatch):
    from soc_agent.agent_cli import main

    calls = []
    monkeypatch.setattr(release, "register", lambda h, r: calls.append((h, r)) or {})
    monkeypatch.setattr(release, "prepare", lambda h: {"status": "PREPARED_NOT_AUTHORIZED"})
    assert (
        main(["setup", "--home", str(tmp_path), "--installed-release", str(tmp_path / "release")])
        == 0
    )
    assert calls == [(tmp_path, tmp_path / "release")]


def test_session_catalogue_and_gui_historical_attach_do_not_start_backend(tmp_path, monkeypatch):
    from tests.unit.test_agent_cli import configured

    from soc_agent.gui import __main__ as gui

    home, _ = configured(tmp_path)
    old = json.loads((home / "agent.json").read_text())
    put(home / "sessions/old.json", old)
    rows = release.session_profiles(home)
    assert [row["current"] for row in rows] == [True, False]
    assert rows[0]["runtime"] == rows[1]["runtime"]
    calls = []
    monkeypatch.setattr(gui, "main", lambda args: calls.append(args) or 0)
    monkeypatch.setattr(agent_runtime.service, "start", lambda *_: pytest.fail("No start"))
    assert agent_runtime.gui(home, session=1) == 0
    assert calls[0][calls[0].index("--continuous-runtime") + 1] == old["profile"]["runtime"]
    with pytest.raises(ValueError, match="SESSION_INDEX"):
        agent_runtime.gui(home, session=8)


def test_archived_session_tampering_cannot_be_attached(tmp_path):
    put(tmp_path / "agent.json", {"profile": {}, "digest": "wrong"})
    with pytest.raises(ValueError, match="ARCHIVED_PROFILE_INTEGRITY"):
        release.session_profiles(tmp_path)


def test_nonempty_tcx_snapshot_blocks_rotation_even_with_exit_zero(tmp_path, monkeypatch):
    home, execution, _ = session(tmp_path, monkeypatch, consumed=True)
    (execution / "namespace-after-tcx.json").write_text(
        json.dumps({"returncode": 0, "stdout": '[{"tc":[{"id":123}]}]'})
    )
    with pytest.raises(ValueError, match="TCX_CLEANUP_UNVERIFIED"):
        release.prior_session(home)


@pytest.mark.asyncio
async def test_gui_session_catalogue_uses_read_only_attachment(tmp_path, monkeypatch):
    from tests.unit.test_agent_cli import configured

    from soc_agent.gui.backend import Backend, GUIConfig

    home, _ = configured(tmp_path)
    put(home / "sessions/old.json", json.loads((home / "agent.json").read_text()))
    backend = Backend(GUIConfig(data_directory=tmp_path / "gui", operator_home=home))
    rows = await backend.operator_sessions()
    assert len(rows["sessions"]) == 2
    attached = []

    async def attach(path):
        attached.append(path)
        return {"state": "STOPPED", "collection_live": False}

    monkeypatch.setattr(backend, "continuous_attach", attach)
    result = await backend.operator_session_attach(1)
    assert result["collection_live"] is False
    assert attached == [str(agent_runtime.profile(home).runtime)]
    assert backend.config.continuous_execution_evidence is None
    with pytest.raises(ValueError, match="SESSION_INDEX"):
        await backend.operator_session_attach(-1)


def test_installed_preview_validates_release_without_rotation(registered, monkeypatch):
    home, _ = registered
    monkeypatch.setattr(release, "prepare", lambda _: pytest.fail("Preview cannot rotate"))
    monkeypatch.setattr(
        agent_runtime, "start_preview", lambda _: {"status": "PREVIEW", "executed": False}
    )
    assert agent_runtime.start(home, preview=True) == {"status": "PREVIEW", "executed": False}


def test_update_without_valid_previous_cleanup_cannot_replace_profile(registered, monkeypatch):
    home, template = registered
    original = (home / "installed-release.json").read_bytes()
    monkeypatch.setattr(
        release, "prior_session", lambda _: (_ for _ in ()).throw(ValueError("UNVERIFIED_CLEANUP"))
    )
    with pytest.raises(ValueError, match="UNVERIFIED_CLEANUP"):
        release.update(home, template)
    assert (home / "installed-release.json").read_bytes() == original
    assert not (home / "release-history").exists()


def test_operator_header_discloses_permissions_and_session():
    from soc_agent.gui.operator_view import continuous_status_line

    value = dict(
        continuous={"source": "NATIVE_SERVICE", "state": "STOPPED"},
        operation=dict(
            release="fixed-version",
            session="fresh-session",
            integrity="PASS",
            model_authority="EXACT_SEALED_ELIGIBLE_HUMAN_REVIEW",
            api_authority="EXACT_INCIDENT_REVISION_HUMAN_REVIEW",
        ),
    )
    text = continuous_status_line(value)
    assert "fixed-version" in text and "fresh-session" in text
    assert "HUMAN_REVIEW" in text and "ERROR" not in text


@pytest.mark.parametrize("calls,budget", [(2, "0.05"), (1, "0.01")])
def test_new_session_api_request_matches_narrowed_proposal(calls, budget):
    import ast

    from soc_agent.agent_session import bind_api_limits

    source = (
        "request = dict(incident_id='fixed', evidence_revision='fixed', "
        "max_calls=2, budget_usd='1.00')"
    )
    result = bind_api_limits(source, calls=calls, budget_usd=budget)
    fields = {
        key.arg: ast.literal_eval(key.value) for key in ast.parse(result).body[0].value.keywords
    }
    assert fields == dict(
        incident_id="fixed", evidence_revision="fixed", max_calls=calls, budget_usd=budget
    )


@pytest.mark.parametrize(
    "calls,budget", [(20, "1.00"), (2, "2"), (2, "NaN"), (2, "-1"), (0, ".05")]
)
def test_factory_cannot_expand_api_contract(calls, budget):
    from soc_agent.agent_session import bind_api_limits

    source = (
        "request = dict(incident_id='fixed', evidence_revision='fixed', "
        "max_calls=2, budget_usd='1.00')"
    )
    with pytest.raises(ValueError, match="EXPANSION_FORBIDDEN"):
        bind_api_limits(source, calls=calls, budget_usd=budget)


def test_factory_rejects_missing_or_ambiguous_api_template():
    from soc_agent.agent_session import bind_api_limits

    for text in [
        "request = {}",
        "request=dict(incident_id='i', evidence_revision='r', max_calls=2, budget_usd='1')\n" * 2,
    ]:
        with pytest.raises(ValueError, match="EXACT_REQUEST_TEMPLATE"):
            bind_api_limits(text, calls=2, budget_usd=".05")
