"""Dashboard queries observe real durable snapshots without advancing the agent."""

import ast
import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.api.dashboard.models import SignalView
from soc_agent.api.dashboard.query import project_overview
from soc_agent.api.dashboard.render import CSP, CSS, render_overview
from soc_agent.assessment import FusionAssessmentResult, ThreatAssessment
from soc_agent.investigation.runtime.persistence.models import WorkflowCheckpoint
from soc_agent.review.persistence.dashboard import DashboardSource, read_dashboard_snapshot
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.security_ai.fusion import MultiModelFusionEngine
from soc_agent.state import IncidentState
from soc_agent.state.evidence import utc_now
from tests.fusion_support import fusion_input, model_bindings
from tests.integration.api.conftest import step
from tests.scenarios.test_security_ai_fusion import authentication_features, network_features


async def request(a, path="/dashboard", *, method="GET", token=True):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        messages.append(message)

    await a.app(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(b"authorization", f"Bearer {a.token}".encode())] if token else [],
        },
        receive,
        send,
    )
    return messages[0]["status"], dict(messages[0]["headers"]), messages[1]["body"].decode()


def dump(store):
    with store.database.transaction(write=False) as connection:
        return tuple(connection.iterdump())


def fail(*args, **kwargs):
    raise AssertionError("Dashboard must not invoke runtime or mutate governance")


def test_empty_projection_and_immutable_unknown():
    view = project_overview(())
    assert (
        view.active_incident_count,
        view.active_workflow_count,
        view.human_action_count,
        view.security_signal_count,
    ) == (0, 0, 0, 0)
    assert view.system_status == view.posture == "UNKNOWN"
    assert all(s.state == s.confidence == "UNKNOWN" for s in view.signals)
    assert view == project_overview(())
    with pytest.raises(ValidationError):
        view.system_status = "ONLINE"
    html = render_overview(view, utc_now())
    for text in (
        "SOC Command Center",
        "ACTIVE INCIDENTS",
        "WORKFLOWS IN PROGRESS",
        "HUMAN ACTION REQUIRED",
        "SECURITY SIGNALS",
        "No active incidents",
        "No active workflow",
        "No human actions",
        "No retained signal",
        "No recent activity",
        "Network AI",
        "Authentication AI",
        "Fusion",
        "UNKNOWN",
    ):
        assert text in html
    assert "<script" not in html and "<form" not in html


@pytest.mark.asyncio
async def test_authorized_html_json_and_read_only_boundary(api_case, monkeypatch):
    a = api_case()
    before = dump(a.c.store)
    calls = a.c.llm.calls
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    monkeypatch.setattr(a.service, "create", fail)
    monkeypatch.setattr(a.service, "approve", fail)
    monkeypatch.setattr(a.service, "promote", fail)
    status, headers, html = await request(a)
    assert status == 200 and headers[b"content-type"] == b"text/html; charset=utf-8"
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"content-security-policy"].decode() == CSP
    assert base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode() in CSP
    assert "Agent Workflow" in html and "Recent Activity" in html
    status, _, body = await request(a, "/api/dashboard/overview")
    assert status == 200
    view = json.loads(body)
    assert view["active_incident_count"] == len(view["incidents"]) == 1
    assert view["active_workflow_count"] == 1
    assert view["incidents"][0]["workflow"]["next_step"] == "observe"
    assert view["incidents"][0]["evidence_count"] == 1
    assert view["posture"] == "INVESTIGATING"
    assert dump(a.c.store) == before and a.c.llm.calls == calls
    assert all(t.call_count == 0 for t in a.c.mocks.values())


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/dashboard", "/api/dashboard/overview"])
async def test_auth_and_method_denial(api_case, path):
    a = api_case()
    assert (await request(a, path, token=False))[0] == 401
    assert (await request(a, path, method="POST"))[0] == 405
    assert (await request(a, path, method="PATCH"))[0] == 405
    a.access.denied = True
    assert (await request(a, path))[0] == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("denied_operation", ["GET:", "GET:workflow", "GET:artifacts"])
async def test_incident_scope_filters_all_aggregates(api_case, denied_operation):
    a = api_case()
    operations = []

    def access(principal, identity, operation):
        operations.append(operation)
        if identity == a.c.incident_id and operation == denied_operation:
            raise ValueError("Restricted object")

    a.access.require_access = access
    status, _, text = await request(a, "/api/dashboard/overview")
    assert status == 200 and "GET:dashboard" in operations
    body = json.loads(text)
    assert body["active_incident_count"] == body["active_workflow_count"] == 0
    assert body["human_action_count"] == body["security_signal_count"] == 0
    assert body["incidents"] == body["recent_activity"] == []
    assert str(a.c.incident_id) not in text


@pytest.mark.asyncio
async def test_waiting_checkpoint_and_claim_are_observed_not_retried(api_case):
    a = api_case()
    for _ in range(4):
        assert (await step(a))[0] == 200
    before = dump(a.c.store)
    view = a.service.dashboard_overview(lambda _: True)
    assert view.human_action_count == 1
    assert view.human_actions[0].category == "Incident Review"
    assert view.posture == "ACTION REQUIRED"
    saved = a.service.checkpoint(a.c.incident_id)
    assert view.incidents[0].workflow.next_step == saved.result.next_step
    assert dump(a.c.store) == before
    a.service.checkpoints.claim(saved)
    before = dump(a.c.store)
    claimed = a.service.dashboard_overview(lambda _: True)
    assert claimed.posture == "RECOVERY REQUIRED"
    assert claimed.incidents[0].workflow.claimed
    assert "operator inspection" in claimed.human_actions[0].category
    assert dump(a.c.store) == before


def test_ordering_closed_incident_and_no_workflow(api_case):
    a = api_case()
    a.c.store.register(IncidentState(incident_id=uuid4(), status="closed"))
    a.c.store.register(IncidentState(incident_id=uuid4()))
    snapshot = read_dashboard_snapshot(a.c.store, lambda _: True)
    view = project_overview(snapshot)
    assert view.active_incident_count == 2 and view.active_workflow_count == 1
    assert sum(i.workflow is None for i in view.incidents) == 2
    assert view == project_overview(tuple(reversed(snapshot)))
    times = [event.timestamp for event in view.recent_activity]
    assert times == sorted(times, reverse=True)


def test_network_authentication_fusion_and_provenance(api_case):
    a = api_case()
    source = read_dashboard_snapshot(a.c.store, lambda _: True)[0]
    state = source.incident.state
    bindings = model_bindings()
    inputs = tuple(
        fusion_input(
            binding,
            authentication_features() if kind == "authentication_anomaly" else network_features(),
            state,
        )
        for kind, binding in bindings.items()
    )
    fusion = MultiModelFusionEngine(tuple(bindings.values()), tuple(bindings)).fuse(
        incident_id=state.incident_id,
        inputs=inputs,
    )
    assessment = FusionAssessmentResult(
        incident_state=state,
        model_derived_context=fusion,
        threat_assessment=ThreatAssessment(
            incident_id=state.incident_id,
            severity="info",
            confidence=0.5,
            summary="Synthetic test",
            supporting_evidence_ids=(state.evidence[0].evidence_id,),
        ),
    )
    data = source.checkpoint.model_dump()
    data["artifacts"]["assessment"] = assessment
    data["result"]["references"] = (
        {"kind": "assessment", "identity": str(assessment.threat_assessment.assessment_id)},
        {"kind": "fusion", "identity": fusion.fusion_id},
    )
    checkpoint = WorkflowCheckpoint.model_validate(data)
    view = project_overview((DashboardSource(source.incident, checkpoint),))
    assert view.security_signal_count == len(fusion.signals)
    assert all(s.reference and s.run_id == checkpoint.run_id for s in view.signals)
    assert all(s.confidence == "UNKNOWN" for s in view.signals)
    assert view.signals[2].state == fusion.agreement_state.value.upper()
    assert "authentication_anomaly" in view.signals[1].provenance
    assert view.signals[0].provenance[0] in ("network_classifier", "network_anomaly")
    assert all("probability" not in type(signal).model_fields for signal in view.signals)
    assert project_overview((DashboardSource(source.incident, checkpoint),)) == view


def test_untrusted_text_escaped_and_no_raw_evidence(api_case):
    a = api_case()
    view = a.service.dashboard_overview(lambda _: True)
    attack = '<img src=x onerror="alert(1)"><script>attack()</script>'
    incident = view.incidents[0].model_copy(update={"sources": (attack,)})
    signal = SignalView(
        domain="Network AI",
        state=attack,
        reference=attack,
        provenance=(attack,),
        incident_id=incident.incident_id,
    )
    value = view.model_copy(update={"incidents": (incident,), "signals": (signal,)})
    html = render_overview(value, utc_now())
    assert attack not in html and "&lt;img" in html and "&quot;alert(1)&quot;" in html
    assert "<script>" not in html and 'title="<img' not in html
    assert "raw_data" not in html


def test_snapshot_uses_one_transaction_and_rejects_corruption(api_case, monkeypatch):
    a = api_case()
    original = a.c.store.database._connect
    opened = []

    def connect():
        result = original()
        opened.append(result)
        return result

    monkeypatch.setattr(a.c.store.database, "_connect", connect)
    a.service.dashboard_overview(lambda _: True)
    assert len(opened) == 1
    with a.c.store.database.transaction() as connection:
        connection.execute("UPDATE workflow_checkpoints SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        a.service.dashboard_overview(lambda _: True)


def test_presentation_cannot_import_persistence_or_execution():
    root = Path(__file__).parents[3] / "src/soc_agent/api/dashboard"
    tree = ast.parse((root / "render.py").read_text())
    modules = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("persistence" in (name or "") or "execution" in (name or "") for name in modules)
    assert "sqlite" not in (root / "render.py").read_text()
    css = (root / "style.css").read_text()
    assert "max-width:1100px" in css and "max-width:720px" in css
