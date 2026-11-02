"""Human batch review of synthetic Native metadata; NEVER actual model/capture execution."""

import json
from datetime import timedelta

import pytest
from tests.integration.test_tcx_ai_workflow import job

from soc_agent import agent_review
from soc_agent.approval import ApprovalRequest
from soc_agent.continuous.models import ContinuousConfig
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.tcx_analysis import analysis_action
from soc_agent.state.evidence import utc_now


def setup(tmp_path, monkeypatch):
    review = tmp_path / "review"
    runtime = review / "future-runtime"
    (runtime / "inputs").mkdir(parents=True)
    grants = review / "grants"
    grants.mkdir(mode=0o700)
    j = job(native=True)  # Synthetic attestation fixture; the Root boundary is not exercised.
    cfg = ContinuousConfig(
        source="NATIVE_SERVICE",
        input_file=review / "policy.json",
        input_sha256=j.result["tcx"]["data_plane"]["processing"]["plan"]["source_digest"],
        native_model_approvals=grants,
    )
    request = dict(
        runtime_session="TEST_SESSION_NOT_LIVE",
        root_file_map_release_identity=j.release_manifest,
        model_action_review=dict(max_model_invocations=16),
        expires_at=(utc_now() + timedelta(minutes=30)).isoformat(),
    )
    p = review / "approval-request-final-v2.json"
    p.write_text(json.dumps(request))
    p.chmod(0o600)
    pin = digest(j.model_dump(mode="json"))
    source = runtime / "inputs" / (pin + ".json")
    source.write_text(j.model_dump_json())
    source.chmod(0o600)
    monkeypatch.setattr(agent_review, "_context", lambda _: (request, cfg, runtime))
    return review, runtime, grants, j, source, request, cfg


def test_prepare_and_explicit_human_batch_issue_exact_existing_contract(tmp_path, monkeypatch):
    review, runtime, grants, j, source, request, cfg = setup(tmp_path, monkeypatch)
    before = source.read_bytes()
    batch = agent_review.pending_models(review)
    assert len(batch.jobs) == 1 and batch.jobs[0].calls == 2
    assert list(grants.iterdir()) == [] and source.read_bytes() == before
    with pytest.raises(ValueError, match="EXPLICIT_HUMAN"):
        agent_review.approve_models(
            review, digest(batch.model_dump(mode="json")), actor="TEST_ONLY", confirmed=False
        )
    assert list(grants.iterdir()) == []
    result = agent_review.approve_models(
        review, digest(batch.model_dump(mode="json")), actor="TEST_ONLY", confirmed=True
    )
    assert result["jobs"] == 1 and result["capture_started"] is False
    pin = batch.jobs[0].job
    approval = ApprovalRequest.model_validate_json((grants / (pin + ".json")).read_bytes())
    action = analysis_action(j, runtime / "analysis" / ("run-" + pin))
    assert (
        approval.action_id == action.action_id and approval.action_input_json == action.tool_input
    )
    assert approval.decision.decided_by == "TEST_ONLY"
    assert source.read_bytes() == before
    old = (grants / (pin + ".json")).read_bytes()
    with pytest.raises(ValueError, match="BATCH_CHANGED"):
        agent_review.approve_models(
            review, digest(batch.model_dump(mode="json")), actor="TEST_ONLY", confirmed=True
        )
    assert (grants / (pin + ".json")).read_bytes() == old


def test_changed_model_scope_and_budget_never_publish_grant(tmp_path, monkeypatch):
    review, runtime, grants, j, source, request, cfg = setup(tmp_path, monkeypatch)
    request["model_action_review"]["max_model_invocations"] = 1
    with pytest.raises(ValueError, match="SCOPE_LIMIT_EXCEEDED"):
        agent_review.pending_models(review)
    assert list(grants.iterdir()) == []
    request["model_action_review"]["max_model_invocations"] = 16
    other = cfg.model_copy(update={"input_sha256": "0" * 64})
    monkeypatch.setattr(agent_review, "_context", lambda _: (request, other, runtime))
    with pytest.raises(ValueError, match="CAPTURE_SCOPE_MISMATCH"):
        agent_review.pending_models(review)
    assert list(grants.iterdir()) == []


def test_job_tamper_is_not_approved(tmp_path, monkeypatch):
    review, runtime, grants, j, source, request, cfg = setup(tmp_path, monkeypatch)
    batch = agent_review.pending_models(review)
    body = json.loads(source.read_text())
    body["namespace"] = "net:[4026531833]"
    source.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="JOB_PIN_CHANGED"):
        agent_review.approve_models(
            review, digest(batch.model_dump(mode="json")), actor="TEST_ONLY", confirmed=True
        )
    assert not list(grants.glob("*.json"))
