"""Read-only incident traceability against actual durable application contracts."""

import ast
import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from soc_agent.api.dashboard.incident_query import display_text, project_incident
from soc_agent.api.dashboard.incident_render import render_incident
from soc_agent.review.authentication import HumanActionContext
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.incident_detail import read_incident_detail
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.state.evidence import utc_now
from tests.integration.api.conftest import call, step
from tests.integration.api.test_dashboard import dump, fail, request
from tests.integration.api.test_http import decision, promote, review


def detail_path(a, api=False, identity=None):
    prefix = "/api/dashboard/incidents/" if api else "/dashboard/incidents/"
    return prefix + str(identity or a.c.incident_id)


@pytest.mark.asyncio
async def test_detail_summary_navigation_and_missing_artifacts(api_case):
    a = api_case()
    status, headers, html = await request(a, detail_path(a))
    assert status == 200 and headers[b"content-type"] == b"text/html; charset=utf-8"
    assert str(a.c.incident_id) in html and "AUTHORITATIVE STATE" in html
    assert "HUMAN GOVERNANCE BOUNDARY" in html
    for text in (
        "Agent Workflow",
        "Evidence",
        "Agent Observations",
        "Investigation Hypotheses",
        "Threat Assessment NOT AVAILABLE",
        "Incident Decision NOT AVAILABLE",
        "Human Governance",
        "Security AI Signals",
        "Provenance",
        "Artifact Timeline",
    ):
        assert text in html
    status, _, text = await request(a, detail_path(a, True))
    value = json.loads(text)
    assert status == 200 and value["severity"] == "info" and value["status"] == "new"
    assert value["workflow"]["next_step"] == "observe"
    assert value["workflow"]["stages"][0]["status"] == "CURRENT"
    assert value["evidence"][0]["reliability"] is None
    assert all(s["state"] == "UNKNOWN" for s in value["signals"])
    assert "raw_data" not in text and "tool_input" not in text
    assert value["observations"] == value["hypotheses"] == []
    _, _, overview = await request(a)
    assert f'href="{detail_path(a)}"' in overview
    other = uuid4()
    a.service.create(other)
    _, _, new = await request(a, detail_path(a, identity=other))
    assert "Workflow NOT AVAILABLE" in new and "No Evidence records" in new


@pytest.mark.asyncio
@pytest.mark.parametrize("api", [False, True])
async def test_authorization_not_found_and_read_only_method(api_case, api):
    a = api_case()
    path = detail_path(a, api)
    assert (await request(a, path, token=False))[0] == 401
    assert (await request(a, detail_path(a, api, uuid4())))[0] == 404
    assert (await request(a, path, method="POST"))[0] == 405
    assert (await request(a, path, method="PATCH"))[0] == 405
    assert (await request(a, path.rsplit("/", 1)[0] + "/invalid"))[0] == 422
    a.access.denied = True
    assert (await request(a, path))[0] == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation", ["GET:dashboard/incident-detail", "GET:", "GET:trace", "GET:artifacts"]
)
async def test_aggregate_access_does_not_grant_incident_history(api_case, operation):
    a = api_case()
    seen = []

    def access(principal, identity, op):
        seen.append((identity, op))
        if identity == a.c.incident_id and op == operation:
            raise ValueError("Object read denied")

    a.access.require_access = access
    status, _, text = await request(a, detail_path(a))
    assert status == 403 and str(a.c.incident_id) not in text
    assert (None, "GET:dashboard") in seen and (a.c.incident_id, operation) in seen


async def structured_analysis(a, monkeypatch, *, malicious=False):
    text = '<svg onload="attack()">untrusted</svg>' if malicious else "Source-linked test analysis"

    async def analysis(*, request, response_model):
        a.c.llm.calls += 1
        state = a.c.store.load(a.c.incident_id).state
        ids = [str(state.evidence[-1].evidence_id)]
        return response_model.model_validate(
            {
                "observations": [{"ref": "O1", "statement": text, "supporting_evidence_ids": ids}],
                "hypotheses": [
                    {
                        "ref": "H1",
                        "statement": text,
                        "supporting_evidence_ids": ids,
                        "confidence": 0.4,
                    }
                ],
                "assessment": {
                    "severity": "high",
                    "confidence": 0.6,
                    "summary": text,
                    "supporting_evidence_ids": ids,
                    "supporting_observation_refs": ["O1"],
                    "supporting_hypothesis_refs": ["H1"],
                },
            }
        )

    monkeypatch.setattr(a.c.llm, "generate_structured", analysis)
    await decision(a)
    return text


@pytest.mark.asyncio
async def test_artifact_classes_advisory_state_and_exact_links(api_case, monkeypatch):
    a = api_case()
    await structured_analysis(a, monkeypatch)
    source = read_incident_detail(
        a.c.store, a.service.checkpoints, a.service.execution, a.c.incident_id
    )
    view = project_incident(source)
    assert view.severity == "info" and view.assessment.severity == "high"
    assert len(view.evidence) == len(view.observations) == len(view.hypotheses) == 1
    assert view.hypotheses[0].confidence == 0.4
    assert view.observations[0].supporting[0].identity == str(view.evidence[0].evidence_id)
    assert view.observations[0].supporting[0].anchor == f"evidence-{view.evidence[0].evidence_id}"
    assert view.decision.outcome == "suspicion_for_review"
    assert view.decision.decision_id == source.source.checkpoint.artifacts.decision.decision_id
    assert "created_at" not in type(view.decision).model_fields
    assert all("timestamp" not in type(t).model_fields for t in view.workflow.trace)
    assert all(
        s.permission == "NOT AVAILABLE"
        for s in (view.investigation.steps if view.investigation else ())
    )
    assert project_incident(source) == view
    assert [t.timestamp for t in view.timeline] == sorted(t.timestamp for t in view.timeline)
    assert any(
        p.target.label == "Decision" and p.source.identity == str(view.assessment.assessment_id)
        for p in view.provenance
    )
    html = render_incident(view, utc_now())
    assert "ADVISORY" in html and "UNVERIFIED HYPOTHESIS" in html
    assert f'href="#evidence-{view.evidence[0].evidence_id}"' in html
    assert "<pre>" not in html and "<form" not in html and "<script" not in html
    with pytest.raises(ValidationError):
        view.severity = "critical"


@pytest.mark.asyncio
async def test_governance_records_and_waiting_claim_remain_distinct(api_case):
    a = api_case()
    await decision(a)
    status, recorded, _, _ = await review(a)
    assert status == 200
    before = dump(a.c.store)
    view = a.service.dashboard_incident(a.c.incident_id)
    assert {g.domain for g in view.governance} == {"Incident Review request", "Incident Review"}
    assert any(g.status == recorded["outcome"] for g in view.governance)
    assert any(s.step == "govern" and s.status == "WAITING" for s in view.workflow.stages)
    assert dump(a.c.store) == before
    saved = a.service.checkpoint(a.c.incident_id)
    a.service.checkpoints.claim(saved)
    view = a.service.dashboard_incident(a.c.incident_id)
    assert view.workflow.claimed
    assert (
        next(s for s in view.workflow.stages if s.step == saved.result.next_step).status
        == "UNKNOWN"
    )
    assert "Outstanding claim: outcome UNKNOWN" in render_incident(view, utc_now())


@pytest.mark.asyncio
async def test_untrusted_artifact_text_escaped_and_inputs_withheld(api_case, monkeypatch):
    a = api_case()
    attack = await structured_analysis(a, monkeypatch, malicious=True)
    evidence = a.c.store.load(a.c.incident_id).state.evidence[0]
    # A real appended record may carry sensitive raw content; no raw payload enters the DTO.
    from soc_agent.state import Evidence

    saved = a.c.store.load(a.c.incident_id)
    a.c.store.append_evidence(
        saved.anchor,
        Evidence(
            incident_id=a.c.incident_id,
            source="untrusted-source",
            summary=attack,
            raw_data='{"password":"not-for-display"}',
            observed_at=utc_now(),
        ),
    )
    _, _, html = await request(a, detail_path(a))
    assert attack not in html and "&lt;svg" in html and "&quot;attack()&quot;" in html
    assert "not-for-display" not in html and "<pre>" not in html
    assert "Retained workflow source differs" in html
    _, _, body = await request(a, detail_path(a, True))
    assert "raw_data" not in body and "password" not in body
    assert str(evidence.evidence_id) in body
    assert (
        display_text("Authorization: Bearer hidden-value")
        == "[WITHHELD: authentication material marker]"
    )
    assert "hidden-value" not in display_text("token=hidden-value")


@pytest.mark.asyncio
@pytest.mark.parametrize("uncertain", [False, True])
async def test_response_promotion_and_durable_execution_are_separate(api_case, uncertain):
    a = api_case(responses=[TimeoutError("private-input")] if uncertain else None)
    identity = await promote(a)
    view = a.service.dashboard_incident(a.c.incident_id)
    assert view.responses[0].status == "PROPOSED" and view.executions == ()
    # A memory-only response promotion cannot be inferred as durable execution evidence.
    assert (await step(a, promoted_id=identity))[0] == 200
    view = a.service.dashboard_incident(a.c.incident_id)
    assert view.responses[0].status == "PROMOTED"
    assert view.executions[0].status == "pending"
    assert {g.domain for g in view.governance} >= {"Incident Review", "Response Action Review"}
    assert (await step(a, execute=True))[0] == 200
    before = dump(a.c.store)
    view = a.service.dashboard_incident(a.c.incident_id)
    assert view.executions[0].status == ("uncertain" if uncertain else "succeeded")
    assert view.responses[0].status == "PROMOTED"
    assert view.executions[0].started_at is not None
    html = render_incident(view, utc_now())
    assert "private-input" not in html
    if uncertain:
        assert ">UNCERTAIN<" in html and ">FAILED<" not in html
    assert dump(a.c.store) == before
    if uncertain:
        from soc_agent.execution.durable import ReconciliationRequest

        recorded = a.c.executor.store.load(view.executions[0].execution_id)
        request_value = ReconciliationRequest(
            execution_intent_id=recorded.intent.execution_intent_id,
            incident_id=a.c.incident_id,
            expected_revision=recorded.revision,
            outcome="confirmed_succeeded",
            reason="Explicit sandbox reconciliation",
            references=("test-ticket",),
        )
        credential = a.b.issue(
            HumanActionContext(
                incident_id=a.c.incident_id,
                action=HumanAction.RECONCILE_EXECUTION,
                binding_digest=content_digest(request_value),
                decision_id=a.service.checkpoint(a.c.incident_id).artifacts.decision.decision_id,
            ),
            (HumanRole.APPROVER,),
        )
        assert (
            await call(
                a.app,
                "POST",
                a.base + "/reconciliation",
                request_value.model_dump(mode="json"),
                credential,
            )
        )[0] == 200
        refreshed = a.service.dashboard_incident(a.c.incident_id)
        assert refreshed.executions[0].reconciliation == "confirmed_succeeded"
        assert any(g.domain == "Durable Reconciliation" for g in refreshed.governance)
        assert a.c.mocks["inspect_logs"].call_count == 1


@pytest.mark.asyncio
async def test_durable_tool_approval_is_not_incident_or_response_review(api_case):
    a = api_case(severities=("high",))
    identity = await promote(a, write=True)
    assert (await step(a, promoted_id=identity))[0] == 200
    _, pending = await call(
        a.app,
        "POST",
        a.base + "/approval-requests",
        {"promoted_id": identity, "reason": "Explicit test action"},
        a.token,
    )
    value = a.service.promoted(a.c.incident_id, identity)
    intent = a.c.bridge.approval_intent(value, UUID(pending["approval_id"]))
    token = a.b.issue(
        HumanActionContext(
            incident_id=a.c.incident_id,
            action=HumanAction.APPROVE_PROMOTED_TOOL,
            binding_digest=content_digest(intent),
            decision_id=a.service.checkpoint(a.c.incident_id).artifacts.decision.decision_id,
        ),
        (HumanRole.APPROVER,),
    )
    assert (
        await call(
            a.app,
            "POST",
            a.base + "/approvals",
            {"promoted_id": identity, "approval_id": pending["approval_id"]},
            token,
        )
    )[0] == 200
    assert (await step(a, promoted_id=identity, approval_id=pending["approval_id"]))[0] == 200
    view = a.service.dashboard_incident(a.c.incident_id)
    assert {g.domain for g in view.governance} >= {
        "Incident Review",
        "Response Action Review",
        "Tool Approval",
    }
    approval = next(g for g in view.governance if g.domain == "Tool Approval")
    assert approval.status == "approved" and approval.timestamp is not None
    assert view.executions[0].status == "pending"
    assert a.c.mocks["test_response"].call_count == 0


@pytest.mark.asyncio
async def test_single_read_snapshot_and_no_authority_calls(api_case, monkeypatch):
    a = api_case()
    await decision(a)
    before = dump(a.c.store)
    llm_calls = a.c.llm.calls
    original = a.c.store.database._connect
    opened = []

    def connect():
        result = original()
        opened.append(result)
        return result

    monkeypatch.setattr(a.c.store.database, "_connect", connect)
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    for name in ("create", "approve", "record_review", "promote", "reconcile"):
        monkeypatch.setattr(a.service, name, fail)
    assert (await request(a, detail_path(a)))[0] == 200
    assert len(opened) == 1
    assert dump(a.c.store) == before and a.c.llm.calls == llm_calls
    assert all(t.call_count == 0 for t in a.c.mocks.values())


def test_trace_corruption_fails_closed_and_presentation_has_no_database(api_case):
    a = api_case()
    with a.c.store.database.transaction() as connection:
        connection.execute("UPDATE workflow_trace SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        a.service.dashboard_incident(a.c.incident_id)
    root = Path(__file__).parents[3] / "src/soc_agent/api/dashboard"
    source = (root / "incident_render.py").read_text()
    tree = ast.parse(source)
    imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert all("persistence" not in name and "execution" not in name for name in imports)
    assert "sqlite" not in source


@pytest.mark.asyncio
async def test_stored_fusion_unknown_and_no_inference_on_detail(api_case, monkeypatch):
    from soc_agent.security_ai.fusion import MultiModelFusionEngine
    from tests.fusion_support import fusion_input, model_bindings
    from tests.scenarios.test_security_ai_fusion import authentication_features, network_features

    a = api_case()
    bindings = model_bindings()
    values = []

    async def model_context(state):
        inputs = tuple(
            fusion_input(
                binding,
                authentication_features()
                if kind == "authentication_anomaly"
                else network_features(),
                state,
            )
            for kind, binding in bindings.items()
        )
        value = MultiModelFusionEngine(tuple(bindings.values()), tuple(bindings)).fuse(
            incident_id=state.incident_id, inputs=inputs
        )
        values.append(value)
        return value

    old_factory = a.service.runtime_factory

    def factory():
        runtime = old_factory()
        runtime._models = model_context
        return runtime

    async def analysis(*, request, response_model):
        a.c.llm.calls += 1
        state = a.c.store.load(a.c.incident_id).state
        return response_model.model_validate(
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.5,
                    "summary": "Synthetic model-derived context",
                    "supporting_evidence_ids": [str(state.evidence[0].evidence_id)],
                    "supporting_observation_refs": [],
                    "supporting_hypothesis_refs": [],
                },
            }
        )

    monkeypatch.setattr(a.service, "runtime_factory", factory)
    monkeypatch.setattr(a.c.llm, "generate_structured", analysis)
    await decision(a)
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    before = dump(a.c.store)
    detail = a.service.dashboard_incident(a.c.incident_id)
    assert all(s.reference and s.confidence == "UNKNOWN" for s in detail.signals)
    assert detail.signals[2].state == values[0].agreement_state.value.upper()
    assert detail.assessment.fusion_reference == values[0].fusion_id
    assert "authentication_anomaly" in detail.signals[1].provenance
    assert dump(a.c.store) == before and len(values) == 1


@pytest.mark.asyncio
async def test_incident_linked_outcome_is_read_not_recomputed(api_case, monkeypatch):
    from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator, migrate_evaluations
    from soc_agent.experience import ExperienceCaptureService, ExperienceStore, migrate_experiences
    from soc_agent.feedback.schema import migrate_feedback

    a = api_case()
    await decision(a)
    migrate_experiences(a.c.store.database)
    migrate_evaluations(a.c.store.database)
    experiences = ExperienceStore(a.c.store)
    captured = ExperienceCaptureService(experiences).capture(a.c.incident_id)
    recorded = ExperienceEvaluator(EvaluationStore(experiences)).evaluate(captured.experience_id)
    monkeypatch.setattr(ExperienceEvaluator, "evaluate", fail)
    monkeypatch.setattr(ExperienceCaptureService, "capture", fail)
    before = dump(a.c.store)
    detail = a.service.dashboard_incident(a.c.incident_id)
    assert len(detail.outcomes) == 1
    assert detail.outcomes[0].evaluation_id == recorded.evaluation_id
    assert detail.outcomes[0].run_id == captured.content.run_id
    assert detail.outcomes[0].feedback_count is None
    assert detail.outcomes[0].execution_outcome == recorded.content.execution_outcome.value
    assert dump(a.c.store) == before
    migrate_feedback(a.c.store.database)
    assert a.service.dashboard_incident(a.c.incident_id).outcomes[0].feedback_count == 0


@pytest.mark.asyncio
async def test_state_change_authorization_and_application_are_separate(api_case):
    from soc_agent.review.models import SeverityChange

    a = api_case()
    await decision(a)
    assert (await review(a))[0] == 200
    recorded = a.c.reviews.reviews()[0]
    proposed = a.c.reviews.propose_change(
        recorded,
        changes=(SeverityChange(before="info", after="high"),),
        reason="Explicit human metadata change",
    )
    credential = a.b.issue(
        HumanActionContext(
            incident_id=a.c.incident_id,
            action=HumanAction.AUTHORIZE_STATE_CHANGE,
            binding_digest=content_digest(proposed),
            decision_id=recorded.target.decision_id,
        ),
        (HumanRole.ADMIN,),
    )
    authorized = a.c.reviews.authorize_change(proposed, recorded, credential=credential)
    detail = a.service.dashboard_incident(a.c.incident_id)
    assert detail.severity == "info"
    assert {g.domain for g in detail.governance} >= {
        "State Change Request",
        "State Change Authorization",
    }
    assert not any(g.domain == "State Change Application" for g in detail.governance)
    saved = a.c.store.load(a.c.incident_id)
    decision_artifact = a.service.checkpoint(a.c.incident_id).artifacts.decision
    a.c.reviews.apply(saved.state, decision_artifact, recorded, proposed, authorized)
    before = dump(a.c.store)
    detail = a.service.dashboard_incident(a.c.incident_id)
    assert detail.severity == "high" and detail.assessment.severity == "info"
    assert not detail.workflow.matches_current_state
    assert any(
        g.domain == "State Change Application" and g.status == "applied" for g in detail.governance
    )
    assert dump(a.c.store) == before


@pytest.mark.asyncio
async def test_retained_investigation_step_metadata_not_current_registry(api_case):
    a = api_case(evidence=False, plans=("private-target-not-for-display",))
    for _ in range(8):
        assert (await step(a))[0] == 200
        saved = a.service.checkpoint(a.c.incident_id)
        if saved.artifacts.investigation and any(
            s.status == "completed" for s in saved.artifacts.investigation.steps
        ):
            break
    else:
        pytest.fail("Expected a completed retained investigation step")
    before = dump(a.c.store)
    calls = a.c.mocks["inspect_logs"].call_count
    view = a.service.dashboard_incident(a.c.incident_id)
    assert view.investigation.steps[0].status == "completed"
    assert view.investigation.steps[0].evidence.identity == str(
        saved.artifacts.investigation.steps[0].evidence_id
    )
    assert view.investigation.steps[0].permission == "NOT AVAILABLE"
    assert view.investigation.strategy_provenance == "NOT AVAILABLE"
    assert "private-target-not-for-display" in saved.artifacts.investigation.steps[0].tool_input
    html = render_incident(view, utc_now())
    assert "private-target-not-for-display" not in html and "Tool inputs are withheld" in html
    assert "private-target-not-for-display" not in view.model_dump_json()
    assert dump(a.c.store) == before and a.c.mocks["inspect_logs"].call_count == calls
