"""Monitoring reads retained signals without inference, authority or invented telemetry."""

import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from soc_agent.api.dashboard.security_ai_query import project_security_ai
from soc_agent.api.dashboard.security_ai_render import render_security_ai
from soc_agent.review.persistence.models import StoredDataError
from soc_agent.review.persistence.security_ai_monitor import read_security_ai_snapshot
from soc_agent.security_ai.authentication.anomaly import AuthenticationAnomalyDetector
from soc_agent.security_ai.fusion import MultiModelFusionEngine
from soc_agent.security_ai.network.anomaly import NetworkAnomalyDetector
from soc_agent.security_ai.network.classifier import NetworkAttackClassifier
from soc_agent.security_ai.packaging.package import ModelPackage
from tests.fusion_support import fusion_input, model_bindings
from tests.integration.api.test_dashboard import dump, fail, request
from tests.integration.api.test_http import decision
from tests.scenarios.test_security_ai_fusion import authentication_features, network_features

HTML = "/dashboard/security-ai"
API = "/api/dashboard/security-ai"
KINDS = ("network_classifier", "network_anomaly", "authentication_anomaly")


async def retained(a, monkeypatch, kinds=KINDS, unavailable=()):
    """Seed through the real deterministic workflow, not a monitoring-only DB record."""
    bindings = model_bindings()
    results = []

    async def model_context(state):
        inputs = tuple(
            fusion_input(
                bindings[kind],
                authentication_features()
                if kind == "authentication_anomaly"
                else network_features(),
                state,
            )
            for kind in kinds
        )
        value = MultiModelFusionEngine(tuple(bindings.values()), KINDS).fuse(
            incident_id=state.incident_id, inputs=inputs, unavailable=unavailable
        )
        results.append(value)
        return value

    original = a.service.runtime_factory

    def factory():
        runtime = original()
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
                    "summary": "Synthetic retained model context",
                    "supporting_evidence_ids": [str(state.evidence[0].evidence_id)],
                    "supporting_observation_refs": [],
                    "supporting_hypothesis_refs": [],
                },
            }
        )

    monkeypatch.setattr(a.service, "runtime_factory", factory)
    monkeypatch.setattr(a.c.llm, "generate_structured", analysis)
    await decision(a)
    assert len(results) == 1
    return results[0]


def test_empty_unknown_immutable_and_navigation():
    view = project_security_ai(())
    assert view.system_status == "UNKNOWN"
    assert view.linked_incident_count == view.retained_signal_count == 0
    assert view.latest_signal_at is None
    assert [m.kind for m in view.models] == list(KINDS)
    assert all(m.availability == m.signal_state == "UNKNOWN" for m in view.models)
    assert all(not m.metadata_available and m.model_version is None for m in view.models)
    assert view == project_security_ai(())
    with pytest.raises(ValidationError):
        view.system_status = "ONLINE"
    html = render_security_ai(view)
    for text in (
        "Security AI Monitoring",
        "Network XGBoost",
        "Network IsolationForest",
        "Authentication IsolationForest",
        "Fusion context NOT AVAILABLE",
        "No retained model signals",
        "UNKNOWN",
        "not Evidence",
    ):
        assert text in html
    assert "<form" not in html and "<script" not in html and "<pre" not in html
    assert "HEALTHY" not in html and "SAFE" not in html


@pytest.mark.asyncio
@pytest.mark.parametrize("path", [HTML, API])
async def test_authentication_methods_aggregate_permission(api_case, path):
    a = api_case()
    assert (await request(a, path, token=False))[0] == 401
    assert (await request(a, path, method="POST"))[0] == 405
    assert (await request(a, path, method="PATCH"))[0] == 405
    a.access.denied = True
    assert (await request(a, path))[0] == 403


@pytest.mark.asyncio
async def test_stored_models_exact_values_provenance_and_semantics(api_case, monkeypatch):
    a = api_case()
    fusion = await retained(a, monkeypatch)
    view = a.service.dashboard_security_ai(lambda _: True)
    assert view.retained_signal_count == len(fusion.signals) == 3
    assert view.linked_incident_count == 1
    assert view.latest_signal_at == max(s.source_created_at for s in fusion.signals)
    assert len(view.latest_retained_signals) == 3
    bindings = {b.manifest_digest: b for b in fusion.model_references}
    for model in view.models:
        contribution = next(c for c in fusion.contributions if c.model_kind == model.kind)
        binding = bindings[contribution.model_reference]
        assert model.availability == "AVAILABLE" and model.metadata_available
        assert model.manifest_digest == contribution.model_reference
        assert model.model_version == binding.manifest.model_version
        assert model.feature_count == len(binding.manifest.ordered_feature_names)
        assert model.feature_names == binding.manifest.ordered_feature_names
        assert model.integrity_status == "UNKNOWN"
        assert model.incident_id == a.c.incident_id
        assert model.assessment_id and model.run_id and model.source_result_ids
        assert model.signal_ids == contribution.signal_ids
        assert model.source_record_count == len(contribution.provenance.sources)
        if model.kind == "network_classifier":
            assert model.class_probabilities == tuple(
                (p.label, p.probability) for p in contribution.scores.class_probabilities
            )
            assert not model.values
        else:
            assert not model.class_probabilities
            values = {v.name: v.value for v in model.values}
            assert values["Raw score_samples"] == contribution.scores.raw_score
            assert values["Empirical anomaly rank"] == contribution.scores.anomaly_score
            assert values["Normalization decision"] == contribution.scores.is_anomaly
    context = view.fusion_contexts[0]
    assert context.fusion_id == fusion.fusion_id
    assert context.agreement == fusion.agreement_state.value
    assert context.confidence == "unknown"
    assert context.created_at == fusion.created_at
    assert context.limitations == fusion.limitations
    assert view == a.service.dashboard_security_ai(lambda _: True)
    status, headers, html = await request(a, HTML)
    assert status == 200 and headers[b"content-type"] == b"text/html; charset=utf-8"
    assert headers[b"cache-control"] == b"no-store" and b"content-security-policy" in headers
    assert "MODEL CLASS PROBABILITY" in html and "ANOMALY MEASUREMENTS" in html
    assert "Anomaly score is not an attack probability" in html
    assert "Fusion agreement is not statistical confidence" in html
    assert "CONFIDENCE" in html and "UNKNOWN" in html
    assert f"/dashboard/incidents/{a.c.incident_id}" in html
    _, _, overview = await request(a)
    assert f'href="{HTML}"' in overview
    status, _, body = await request(a, API)
    assert status == 200 and json.loads(body) == view.model_dump(mode="json")
    for private in ("training_configuration", "normalization", "raw_data", "feature_values"):
        assert f'"{private}"' not in body
    assert "latency_ms" not in body and "accuracy" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("kinds", [(), ("network_classifier",), ("authentication_anomaly",)])
async def test_partial_retained_contexts_never_invent_missing_signals(api_case, monkeypatch, kinds):
    a = api_case()
    fusion = await retained(a, monkeypatch, kinds)
    view = a.service.dashboard_security_ai(lambda _: True)
    assert len(view.latest_retained_signals) == len(kinds)
    assert view.retained_signal_count == len(kinds)
    assert {m.kind for m in view.models if m.availability == "AVAILABLE"} == set(kinds)
    for model in view.models:
        if model.kind not in kinds:
            assert model.signal_state == "UNKNOWN" and model.last_observed is None
            assert not model.values and not model.class_probabilities
    if not kinds:
        assert view.latest_signal_at is None and fusion.created_at is None
        assert all(m.availability == "UNKNOWN" for m in view.models)
    assert view.fusion_contexts[0].confidence == "unknown"
    assert (await request(a, HTML))[0] == 200


@pytest.mark.asyncio
async def test_monitor_never_infers_reassembles_or_mutates(api_case, monkeypatch):
    import soc_agent.assessment.fusion as assessment_fusion
    import soc_agent.security_ai.fusion.result_validation as validation
    import soc_agent.security_ai.packaging.package as packages

    a = api_case()
    await retained(a, monkeypatch)
    before = dump(a.c.store)
    llm_calls = a.c.llm.calls
    tool_calls = {name: t.call_count for name, t in a.c.mocks.items()}
    monkeypatch.setattr(a.service, "runtime_factory", fail)
    monkeypatch.setattr(a.c.llm, "generate_structured", fail)
    monkeypatch.setattr(MultiModelFusionEngine, "fuse", fail)
    monkeypatch.setattr(MultiModelFusionEngine, "_assemble", fail)
    monkeypatch.setattr(validation, "validate_fusion_result", fail)
    monkeypatch.setattr(assessment_fusion, "validate_fusion_result", fail)
    monkeypatch.setattr(packages, "load_package", fail)
    for model in (
        ModelPackage,
        NetworkAttackClassifier,
        NetworkAnomalyDetector,
        AuthenticationAnomalyDetector,
    ):
        monkeypatch.setattr(model, "predict", fail)
    for path in (HTML, API):
        assert (await request(a, path))[0] == 200
    assert dump(a.c.store) == before
    assert a.c.llm.calls == llm_calls
    assert {name: t.call_count for name, t in a.c.mocks.items()} == tool_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["GET:", "GET:artifacts", "GET:dashboard/incident-detail"])
async def test_object_filter_removes_ids_and_counts_before_payload_read(
    api_case, monkeypatch, operation
):
    a = api_case()
    await retained(a, monkeypatch)
    with a.c.store.database.transaction() as connection:
        connection.execute("UPDATE workflow_checkpoints SET payload='not json'")

    def access(principal, identity, op):
        if identity == a.c.incident_id and op == operation:
            raise ValueError("Restricted incident")

    a.access.require_access = access
    status, _, body = await request(a, API)
    assert status == 200 and str(a.c.incident_id) not in body
    view = json.loads(body)
    assert view["linked_incident_count"] == view["retained_signal_count"] == 0
    assert view["fusion_contexts"] == []


@pytest.mark.asyncio
async def test_one_snapshot_and_corruption_fail_closed(api_case, monkeypatch):
    a = api_case()
    await retained(a, monkeypatch)
    opened = []
    original = a.c.store.database._connect

    def connect():
        connection = original()
        opened.append(connection)
        return connection

    monkeypatch.setattr(a.c.store.database, "_connect", connect)
    a.service.dashboard_security_ai(lambda _: True)
    assert len(opened) == 1
    with a.c.store.database.transaction() as connection:
        connection.execute("UPDATE workflow_checkpoints SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        a.service.dashboard_security_ai(lambda _: True)
    status, _, body = await request(a, API)
    assert status >= 500 and "Traceback" not in body and "SELECT" not in body


@pytest.mark.asyncio
async def test_escaped_labels_provenance_and_sensitive_sources_omitted(api_case, monkeypatch):
    a = api_case()
    await retained(a, monkeypatch)
    source = read_security_ai_snapshot(a.c.store, lambda _: True)[0]
    view = project_security_ai((source,))
    attack = '<svg onload="attack()">untrusted</svg>'
    model = view.models[0].model_copy(
        update={
            "model_name": attack,
            "model_version": attack,
            "feature_schema": attack,
            "extractor": attack,
            "signal_state": attack,
            "source_types": (attack,),
            "class_probabilities": ((attack, 0.85),),
        }
    )
    html = render_security_ai(view.model_copy(update={"models": (model,) + view.models[1:]}))
    assert attack not in html and "&lt;svg" in html and "&quot;attack()&quot;" in html
    assert "<svg onload=" not in html
    # Raw source names/identifiers belong to the feature provenance, not the public DTO.
    private = "private-source-user-token"
    contribution = source.fusion.contributions[0]
    record = contribution.provenance.sources[0]
    record = record.model_copy(update={"source": private})
    provenance = contribution.provenance.model_copy(update={"sources": (record,)})
    altered = contribution.model_copy(update={"provenance": provenance})
    fusion = source.fusion.model_copy(
        update={"contributions": (altered,) + source.fusion.contributions[1:]}
    )
    from dataclasses import replace

    projected = project_security_ai((replace(source, fusion=fusion),))
    assert private not in projected.model_dump_json()


def test_presentation_has_no_persistence_or_execution_dependency():
    root = Path(__file__).parents[3] / "src/soc_agent/api/dashboard"
    source = (root / "security_ai_render.py").read_text()
    tree = ast.parse(source)
    modules = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert all("persistence" not in name and "execution" not in name for name in modules)
    assert "sqlite" not in source and "innerHTML" not in source


@pytest.mark.asyncio
async def test_explicit_unavailability_without_manifest_is_not_model_failure(api_case, monkeypatch):
    from soc_agent.security_ai.fusion.models import ModelAvailability

    a = api_case()
    await retained(
        a,
        monkeypatch,
        (),
        (
            ModelAvailability(model_kind="network_anomaly", status="not_run", reason="Not run"),
            ModelAvailability(
                model_kind="authentication_anomaly", status="failed", reason="Unavailable"
            ),
        ),
    )
    view = a.service.dashboard_security_ai(lambda _: True)
    assert view.models[0].availability == "UNKNOWN"
    assert view.models[1].availability == view.models[2].availability == "NOT AVAILABLE"
    assert view.models[1].reported_coverage == "not_run"
    assert view.models[2].reported_coverage == "failed"
    assert all(not m.metadata_available and m.last_observed is None for m in view.models)
    assert view.latest_signal_at is None and not view.latest_retained_signals
    assert "HEALTHY" not in render_security_ai(view)


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["manifest", "assessment", "incident"])
async def test_rehashed_payload_cannot_rebind_retained_sources(api_case, monkeypatch, tamper):
    import hashlib
    from uuid import uuid4

    from soc_agent._json import canonical_json_object

    a = api_case()
    await retained(a, monkeypatch)
    with a.c.store.database.transaction() as connection:
        row = connection.execute("SELECT * FROM workflow_checkpoints").fetchone()
        raw = json.loads(row["payload"])
        fusion = raw["artifacts"]["assessment"]["model_derived_context"]
        if tamper == "manifest":
            fusion["model_references"][0]["manifest"]["model_version"] = "invented"
        elif tamper == "assessment":
            for ref in raw["result"]["references"]:
                if ref["kind"] == "assessment":
                    ref["identity"] = str(uuid4())
        else:
            fusion["incident_id"] = str(uuid4())
        payload = canonical_json_object(raw)
        connection.execute(
            "UPDATE workflow_checkpoints SET payload=?, digest=?",
            (payload, hashlib.sha256(payload.encode()).hexdigest()),
        )
    with pytest.raises(StoredDataError):
        a.service.dashboard_security_ai(lambda _: True)
