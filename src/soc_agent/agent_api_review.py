"""Local human approval of an already prepared exact API investigation input.

Reuses APIRunAuthorization. No credential loading, provider call, capture,
inference, future-input permission or automatic re-authorization happens here.
"""

import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from soc_agent.agent_review import _write_new
from soc_agent.continuous.api_investigation import retained_input
from soc_agent.continuous.cli import observation
from soc_agent.continuous.investigation import from_analysis
from soc_agent.continuous.investigation_models import InvestigationSource, InvestigationTask
from soc_agent.security_ai.api_investigation import APIRunAuthorization
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest
from soc_agent.state.evidence import utc_now


def _json(path: Path) -> dict:
    return json.loads(read_local(path, 131072))


def _sha(path: Path) -> str:
    return hashlib.sha256(read_local(path, 131072)).hexdigest()


def prepared_api_review(review: Path) -> dict:
    from soc_agent.agent_runtime import verify_review

    parent = verify_review(review)
    directory = review.parent / "llm-review"
    request = _json(directory / "api-review-request.json")
    proposal_path = review.parent / "api-scope-proposal.json"
    proposal = _json(proposal_path)
    pins = _json(review / "execution/execution-pins.json")
    if pins.get(str(proposal_path)) != _sha(proposal_path):
        raise ValueError("API_OPERATOR_PROPOSAL_INTEGRITY")
    if (directory / "authorization.json").exists() or (directory / "api-attempt").exists():
        raise ValueError("API_OPERATOR_ATTEMPT_OR_AUTHORIZATION_ALREADY_EXISTS_NO_REPLAY")
    if (
        proposal["native_runtime_session"] != parent["runtime_session"]
        or proposal["source_commit"] != parent["git_commit"]
        or request["git_commit"] != parent["git_commit"]
        or proposal["retries"] != 0
        or request.get("retries") != 0
        or request["max_calls"] > min(2, proposal["max_calls"])
        or request["max_completion_tokens"] > proposal["max_completion_tokens"]
        or request["timeout_seconds"] > proposal["timeout_seconds"]
        or request["timeout_seconds"] > 20
        or Decimal(request["budget_usd"]) > Decimal(proposal["budget_usd"])
    ):
        raise ValueError("API_OPERATOR_SCOPE_EXCEEDED")
    for name in ("base_url", "model", "input_usd_per_million", "output_usd_per_million"):
        left, right = request[name], proposal[name]
        if name.endswith("per_million"):
            left, right = Decimal(left), Decimal(right)
        if left != right:
            raise ValueError("API_OPERATOR_PROVIDER_OR_PRICE_CHANGED")
    body = _json(directory / "retained-input.json")
    task = InvestigationTask.model_validate(body["task"])
    sources = [InvestigationSource.model_validate(s) for s in body["sources"]]
    if (
        digest(retained_input(task, sources)) != request["input_sha256"]
        or _sha(directory / "retained-input.json") != request["input_file_sha256"]
        or str(task.incident_id) != request["incident_id"]
        or str(task.task_id) != request["task_id"]
        or task.revision != request["evidence_revision"]
    ):
        raise ValueError("API_OPERATOR_INPUT_REVISION_CHANGED")
    native = observation(review / "future-runtime")
    if (
        native is None
        or native["store_id"] != parent["runtime_session"]
        or native["configuration"]["source"] != "NATIVE_SERVICE"
    ):
        raise ValueError("API_OPERATOR_NATIVE_SESSION_MISMATCH")
    selected = [
        source
        for source in sources
        if source.role == "NETWORK"
        and source.origin == "REAL_NATIVE"
        and Path(request["native_source"])
        == review / "future-runtime/analysis" / ("run-" + source.reference)
    ]
    if len(selected) != 1:
        raise ValueError("API_OPERATOR_NATIVE_EVIDENCE_BINDING")
    source = selected[0]
    expected = Path(request["native_source"])
    if (
        source.role != "NETWORK"
        or source.origin != "REAL_NATIVE"
        or Path(request["native_source"]) != expected
        or from_analysis(expected, scope=source.scope, namespace=source.namespace) != source
        or request["output_directory"] != str(directory / "api-attempt")
        or request["runtime_directory"] != str(directory / "investigation-runtime")
    ):
        raise ValueError("API_OPERATOR_NATIVE_EVIDENCE_BINDING")
    original = review / "future-runtime/orchestration/tasks" / (str(task.task_id) + ".json")
    if InvestigationTask.model_validate_json(read_local(original, 131072)) != task:
        raise ValueError("API_OPERATOR_ORIGINAL_TASK_CHANGED")
    if _sha(original) != request["original_task_sha256"]:
        raise ValueError("API_OPERATOR_ORIGINAL_TASK_CHANGED")
    # A display decision is bound to these exact bytes, not a user-entered SHA.
    return dict(
        status="HUMAN_EXACT_API_INPUT_REVIEW",
        incident_id=str(task.incident_id),
        task_id=str(task.task_id),
        evidence_revision=task.revision,
        runtime_session=parent["runtime_session"],
        request_sha256=_sha(directory / "api-review-request.json"),
        review_sha256=_sha(directory / "api-approval-review.md"),
        input_sha256=request["input_sha256"],
        model=request["model"],
        base_url=request["base_url"],
        max_calls=request["max_calls"],
        budget_usd=request["budget_usd"],
        timeout_seconds=request["timeout_seconds"],
        max_completion_tokens=request["max_completion_tokens"],
        retries=0,
        credentials_read=False,
        api_calls_started=0,
        original_scope_expires_at=min(
            datetime.fromisoformat(parent["expires_at"]),
            datetime.fromisoformat(proposal["expires_at"]),
            datetime.fromisoformat(request["approval_upper_expiry"]),
        ).isoformat(),
    )


def approve_api_review(review: Path, expected_digest: str, *, actor: str, confirmed: bool) -> dict:
    if confirmed is not True or not actor.strip():
        raise ValueError("EXPLICIT_HUMAN_API_REVIEW_REQUIRED")
    summary = prepared_api_review(review)
    if digest(summary) != expected_digest:
        raise ValueError("API_OPERATOR_REVIEW_CHANGED")
    directory = review.parent / "llm-review"
    request = _json(directory / "api-review-request.json")
    now = utc_now()
    expiry = min(
        now + timedelta(hours=1),
        datetime.fromisoformat(summary["original_scope_expires_at"]),
        datetime.fromisoformat(request["approval_upper_expiry"]),
    )
    authorization = APIRunAuthorization(
        contract="soc-api-investigation-authorization:v1",
        approved_by=actor,
        approval_reference=summary["review_sha256"],
        input_sha256=summary["input_sha256"],
        output_directory=request["output_directory"],
        base_url=summary["base_url"],
        model=summary["model"],
        starts_at=now,
        expires_at=expiry,
        max_calls=summary["max_calls"],
        budget_usd=Decimal(summary["budget_usd"]),
        input_usd_per_million=Decimal(request["input_usd_per_million"]),
        output_usd_per_million=Decimal(request["output_usd_per_million"]),
        pricing_reference=request["pricing_reference"],
        max_completion_tokens=summary["max_completion_tokens"],
        timeout_seconds=summary["timeout_seconds"],
        minimum_interval_seconds=request["minimum_interval_seconds"],
    )
    authorization.active()
    _write_new(
        directory / "operator-human-decision.json",
        dict(actor=actor, decision="APPROVED_WITH_CONDITIONS", summary=summary),
    )
    _write_new(directory / "authorization.json", authorization.model_dump(mode="json"))
    return dict(status="EXACT_API_INPUT_AUTHORIZED", api_calls_started=0, credentials_read=False)
