"""Synthetic walkthrough and loopback read host, never human approval simulation."""

import asyncio
import hashlib
import os
from http.client import HTTPConnection
from threading import Thread
from uuid import uuid4

import pytest

from soc_agent.demo.command_center import (
    DATABASE,
    DemoAccess,
    manifest,
    observation_app,
    open_demo,
    prepare,
    seed,
)
from soc_agent.demo.local_server import local_server, read_response
from soc_agent.demo.scenarios import scenario_event
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence.secure_storage import create_private_directory


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    directory = tmp_path_factory.mktemp("command-center")
    if os.name == "nt":
        directory = directory / "SOC private snapshot"
        create_private_directory(directory, exist_ok=False)
    else:
        directory.chmod(0o700)
    asyncio.run(seed(directory))
    return directory


def digest(service):
    with service.store.database.transaction(write=False) as connection:
        return hashlib.sha256("\n".join(connection.iterdump()).encode()).hexdigest()


def test_fixed_synthetic_reports():
    for name in ("a", "b"):
        assert scenario_event(name) == scenario_event(name)
        assert scenario_event(name).synthetic
        assert scenario_event(name).source == "synthetic-demo"
    assert scenario_event("a").event_id != scenario_event("b").event_id
    with pytest.raises(ValueError):
        scenario_event("future-model")


def test_seed_replay_and_truthful_learning_gate(seeded, monkeypatch):
    service = open_demo(seeded)
    before = digest(service)
    value = manifest(seeded)
    assert len(value.incidents) == 2
    assert asyncio.run(seed(seeded)) == value
    assert digest(service) == before
    subjects = {}
    for identity in value.incidents:
        checkpoint = service.checkpoint(identity)
        subjects[service.ingestion.load(identity).event.subject] = checkpoint
        assert checkpoint.result.waiting_for_human
        assert "Repeated investigation intent" in checkpoint.result.reason
        assert checkpoint.artifacts.assessment is not None
        assert checkpoint.artifacts.decision is not None
        assert checkpoint.artifacts.execution_intent_id is None
        assert len(service.incident(identity).state.evidence) == 1
    assert subjects["demo-alice"].artifacts.assessment.threat_assessment.severity == "info"
    assert subjects["demo-bob"].artifacts.assessment.threat_assessment.severity == "high"
    view = service.dashboard_self_improvement(lambda _: True)
    assert view.experience_count == 2
    assert view.candidate_count == 0
    assert view.active.state == "NONE"
    assert view.active.runtime_consumption == "UNKNOWN"
    assert not view.versions
    with service.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 14
        for table in (
            "analyst_feedback",
            "improvement_candidates",
            "improvement_review_records",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_reject_non_demo_directory(tmp_path):
    (tmp_path / "keep.txt").write_text("existing user file")
    with pytest.raises(ValueError, match="never reset"):
        prepare(tmp_path)
    assert (tmp_path / "keep.txt").read_text() == "existing user file"
    with pytest.raises(FileNotFoundError):
        observation_app(tmp_path)
    assert not (tmp_path / DATABASE).exists()


def test_observer_auth_and_object_boundary(seeded):
    app, observer = observation_app(seeded)
    identity = observer.authenticate(observer._credential)
    assert identity.scopes == ()
    with pytest.raises(HumanAuthorizationDenied):
        observer.authenticate("untrusted")
    with pytest.raises(HumanAuthorizationDenied):
        observer.confirm(None)
    access = DemoAccess(manifest(seeded).incidents)
    with pytest.raises(HumanAuthorizationDenied):
        access.require_access(identity, uuid4(), "GET:dashboard/incident-detail")
    with pytest.raises(HumanAuthorizationDenied):
        access.require_access(identity, None, "POST:reviews")

    async def unauthenticated():
        messages = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(message):
            messages.append(message)

        await app(
            {"type": "http", "method": "GET", "path": "/dashboard", "headers": []}, receive, send
        )
        return messages[0]["status"]

    assert asyncio.run(unauthenticated()) == 401
    assert asyncio.run(read_response(app, observer, f"/dashboard/incidents/{uuid4()}"))[0] == 403


def test_all_dashboard_reads_preserve_snapshot(seeded, monkeypatch):
    app, observer = observation_app(seeded)
    service = app.startup()
    before = digest(service)

    def forbidden(*args, **kwargs):
        raise AssertionError("Read host must not dispatch workflow, approval or inference")

    monkeypatch.setattr(service, "runtime_factory", forbidden)
    monkeypatch.setattr(service, "step", forbidden)
    paths = (
        ("/dashboard", "SOC Command Center"),
        (f"/dashboard/incidents/{manifest(seeded).incidents[0]}", "Incident Detail"),
        ("/dashboard/governance", "Human Governance Inbox"),
        ("/dashboard/security-ai", "Security AI"),
        ("/dashboard/self-improvement", "GOVERNED SELF-IMPROVEMENT"),
    )
    for path, heading in paths:
        status, headers, body = asyncio.run(read_response(app, observer, path))
        assert status == 200
        assert headers[b"content-type"].startswith(b"text/html")
        assert b"content-security-policy" in headers
        assert heading in body.decode()
        assert "DEMO / SYNTHETIC" in body.decode()
        assert not any(secret in body for secret in (observer._credential.encode(),))
    assert digest(service) == before


def test_loopback_host_and_mutation_rejection(seeded):
    server = local_server(seeded, 0)
    assert server.server_address[0] == "127.0.0.1"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:

        def request(method, path, headers=None):
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            status, body = response.status, response.read()
            connection.close()
            return status, body

        assert request("GET", "/dashboard")[0] == 200
        assert request("POST", "/dashboard/governance")[0] == 405
        assert request("GET", "/dashboard", {"Host": "attacker.invalid"})[0] == 403
        assert request("GET", "/dashboard", {"Origin": "https://attacker.invalid"})[0] == 403
        assert request("GET", "/dashboard", {"Sec-Fetch-Site": "cross-site"})[0] == 403
        assert request("GET", "/dashboard?token=untrusted")[0] == 400
        assert request("GET", "/events")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
