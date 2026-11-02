"""Existing API authorization from explicit human review; all Native evidence is a fixture.

No credentials, external calls, Native collection, or inference occur.
"""

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from tests.integration.test_continuous_orchestration import source
from tests.unit.continuous.test_runtime import make

from soc_agent import agent_api_review, agent_runtime
from soc_agent.continuous.api_investigation import retained_input
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.security_ai.api_investigation import APIRunAuthorization
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import utc_now


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def setup_review(tmp_path, monkeypatch):
    review = tmp_path / "native"
    api = tmp_path / "llm-review"
    runtime, store = make(tmp_path)
    tasks = InvestigationTasks(store)
    item = source(origin="REAL_NATIVE", advisory={"raw_payload": "PRIVATE_SOURCE_TEXT"})
    task = tasks.submit(item)
    body = retained_input(task, [item])
    expiry = (utc_now() + timedelta(minutes=30)).isoformat()
    parent = dict(runtime_session=str(uuid4()), git_commit="a" * 40, expires_at=expiry)
    proposal = dict(
        native_runtime_session=parent["runtime_session"],
        source_commit=parent["git_commit"],
        retries=0,
        max_calls=2,
        max_completion_tokens=4096,
        timeout_seconds=20,
        budget_usd=".05",
        base_url="https://api.openai.com/v1",
        model="gpt-5-mini",
        input_usd_per_million=".25",
        output_usd_per_million="2",
        expires_at=expiry,
    )
    put(tmp_path / "api-scope-proposal.json", proposal)
    proposal_sha = hashlib.sha256((tmp_path / "api-scope-proposal.json").read_bytes()).hexdigest()
    put(
        review / "execution/execution-pins.json",
        {str(tmp_path / "api-scope-proposal.json"): proposal_sha},
    )
    put(api / "retained-input.json", body)
    original = review / "future-runtime/orchestration/tasks" / (str(task.task_id) + ".json")
    put(original, task.model_dump(mode="json"))
    request = dict(
        git_commit=parent["git_commit"],
        retries=0,
        max_calls=2,
        max_completion_tokens=4096,
        timeout_seconds=20,
        budget_usd=".05",
        base_url=proposal["base_url"],
        model=proposal["model"],
        input_usd_per_million=".25",
        output_usd_per_million="2",
        input_sha256=digest(body),
        input_file_sha256=hashlib.sha256((api / "retained-input.json").read_bytes()).hexdigest(),
        incident_id=str(task.incident_id),
        task_id=str(task.task_id),
        evidence_revision=task.revision,
        native_source=str(review / "future-runtime/analysis" / ("run-" + item.reference)),
        output_directory=str(api / "api-attempt"),
        runtime_directory=str(api / "investigation-runtime"),
        original_task_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
        approval_upper_expiry=expiry,
        pricing_reference="TEST_FIXED_PRICING",
        minimum_interval_seconds=1,
    )
    put(api / "api-review-request.json", request)
    (api / "api-approval-review.md").write_text("SYNTHETIC INPUT REVIEW NO LIVE AUTHORITY")
    monkeypatch.setattr(agent_runtime, "verify_review", lambda _: parent)
    monkeypatch.setattr(
        agent_api_review,
        "observation",
        lambda _: dict(
            store_id=parent["runtime_session"], configuration=dict(source="NATIVE_SERVICE")
        ),
    )
    monkeypatch.setattr(agent_api_review, "from_analysis", lambda *args, **kwargs: item)
    return review, api, request, parent


def test_exact_human_api_decision_uses_existing_authorization_and_never_reads_key(
    tmp_path, monkeypatch
):
    review, api, request, parent = setup_review(tmp_path, monkeypatch)
    summary = agent_api_review.prepared_api_review(review)
    assert summary["api_calls_started"] == 0 and summary["credentials_read"] is False
    assert "PRIVATE_SOURCE_TEXT" not in json.dumps(summary)
    with pytest.raises(ValueError, match="EXPLICIT_HUMAN_API"):
        agent_api_review.approve_api_review(
            review, digest(summary), actor="TEST_ONLY", confirmed=False
        )
    assert not (api / "authorization.json").exists()
    result = agent_api_review.approve_api_review(
        review, digest(summary), actor="TEST_ONLY", confirmed=True
    )
    assert result["api_calls_started"] == 0 and result["credentials_read"] is False
    auth = APIRunAuthorization.model_validate_json((api / "authorization.json").read_bytes())
    assert auth.input_sha256 == request["input_sha256"] and auth.max_calls == 2
    assert auth.approved_by == "TEST_ONLY" and auth.timeout_seconds == 20
    with pytest.raises(ValueError, match="NO_REPLAY"):
        agent_api_review.approve_api_review(
            review, digest(summary), actor="TEST_ONLY", confirmed=True
        )


@pytest.mark.parametrize("fault", ["price", "model", "calls", "cost", "retry", "input", "session"])
def test_altered_scope_never_issues_authorization(tmp_path, monkeypatch, fault):
    review, api, request, parent = setup_review(tmp_path, monkeypatch)
    if fault == "price":
        request["input_usd_per_million"] = ".01"
    elif fault == "model":
        request["model"] = "unapproved-model"
    elif fault == "calls":
        request["max_calls"] = 20
    elif fault == "cost":
        request["budget_usd"] = "1"
    elif fault == "retry":
        request["retries"] = 1
    elif fault == "input":
        request["input_sha256"] = "f" * 64
    else:
        parent["runtime_session"] = str(uuid4())
    put(api / "api-review-request.json", request)
    with pytest.raises(ValueError):
        agent_api_review.prepared_api_review(review)
    assert not (api / "authorization.json").exists()
