"""Actual adapter + fake HTTP transport. NEVER a claim of real API validation."""

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from soc_agent.llm import LLMError, LLMRequest
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.security_ai.api_investigation import (
    APIInvestigationClient,
    APIInvestigationDraft,
    APIRunAuthorization,
    minimized,
)
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.state.evidence import utc_now
from tests.integration.test_offline_ai_workflow import job


def authorization(directory, body):
    return APIRunAuthorization(
        contract="soc-api-investigation-authorization:v1",
        approved_by="TEST_ONLY_NOT_LIVE",
        approval_reference="FAKE_TRANSPORT_TEST",
        input_sha256=hashlib.sha256(body).hexdigest(),
        output_directory=str(directory.absolute()),
        base_url="https://invalid.example/v1",
        model="test-model",
        starts_at=utc_now() - timedelta(seconds=1),
        expires_at=utc_now() + timedelta(minutes=5),
        budget_usd="1",
        input_usd_per_million="1",
        output_usd_per_million="2",
        pricing_reference="TEST_PRICING_NOT_ACTUAL",
    )


def settings(a):
    return OpenAICompatibleSettings(base_url=a.base_url, model=a.model, api_key="TEST_SECRET")


def response(request):
    prompt = json.loads(request["messages"][1]["content"])
    evidence = next(v for k, v in prompt.items() if k.startswith("EVIDENCE "))
    refs = [e["evidence_id"] for e in evidence]
    if "AVAILABLE TOOLS" in prompt:
        tools = prompt["AVAILABLE TOOLS"]
        return dict(
            goal="Check retained source continuity, anomaly remains unverified",
            steps=[
                dict(
                    tool_name=tools[0]["name"],
                    tool_input=dict(incident_id=prompt["INCIDENT CONTEXT"]["incident_id"]),
                    purpose="Verify local evidence continuity",
                )
            ],
            observed_anomaly_summary="Model anomaly; source not independently authenticated",
            evidence_references=refs,
            hypotheses=[
                dict(
                    statement="Possible distribution shift",
                    priority="medium",
                    supporting_evidence_ids=refs,
                    verification_method="Read retained source report",
                    required_evidence="Independent capture",
                    expected_findings="Continuity only",
                )
            ],
            unknowns=["Attack attribution unknown"],
            risk_assessment="Insufficient evidence",
            recommended_response="Review source evidence",
            approval_requirement="HUMAN_APPROVAL_FOR_HOST_CHANGES",
        )
    return dict(
        observations=[],
        hypotheses=[
            dict(
                ref="H1",
                statement="Possible model drift; uncertain",
                supporting_evidence_ids=refs,
                confidence=0.2,
            )
        ],
        assessment=dict(
            severity="low",
            confidence=0.2,
            summary="Read-only continuity checked; anomaly remains unverified",
            supporting_evidence_ids=refs,
            supporting_hypothesis_refs=["H1"],
        ),
    )


def transport(calls, mutate=None):
    def post(self, body):
        request = json.loads(body)
        calls.append(request)
        content = response(request)
        if mutate:
            content = mutate(content)
        return json.dumps(
            dict(
                choices=[dict(finish_reason="stop", message=dict(content=json.dumps(content)))],
                usage=dict(prompt_tokens=400, completion_tokens=300),
            )
        ).encode()

    return post


async def run(tmp_path, monkeypatch, mutate=None, change=None):
    directory = tmp_path / "attempt"
    source_job = job("anomaly")
    body = source_job.model_dump_json().encode()
    a = authorization(directory, body)
    if change:
        a = APIRunAuthorization.model_validate(a.model_dump() | change)
    calls = []
    monkeypatch.setattr(OpenAICompatibleClient, "_post", transport(calls, mutate))
    w = OfflineWorkflow(directory, api_authorization=a, api_settings=settings(a))
    submitted = dict(utf8=body.decode(), sha256=hashlib.sha256(body).hexdigest())
    w.write("submitted-input.json", submitted)
    w.event("OFFLINE_SUBMITTED_INPUT_RETAINED", submitted)
    result = await w.run(source_job)
    return result, calls, w


@pytest.mark.asyncio
async def test_real_adapter_fake_transport_full_governed_pipeline(tmp_path, monkeypatch):
    result, calls, w = await run(tmp_path, monkeypatch)
    assert result.classification == "UNKNOWN_ANOMALY"
    assert len(result.inference) == 2
    assert result.investigation["status"] == "COMPLETED_READ_ONLY"
    assert len(calls) == result.external_provider_calls == 2
    assert result.investigation["generated_draft"]["unknowns"]
    assert result.investigation["assessment"]["incident_state"]["observations"] == []
    assert result.investigation["assessment"]["incident_state"]["hypotheses"]
    assert result.response["host_remediation"] is False
    assert verify_result(w.directory) == result
    assert len(list(w.directory.glob("api-intent-*.json"))) == 2
    assert len(list(w.directory.glob("api-response-*.json"))) == 2
    assert "TEST_SECRET" not in "".join(p.read_text() for p in w.directory.glob("*.json"))
    with pytest.raises(FileExistsError):
        OfflineWorkflow(w.directory)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["shell", "unknown_evidence", "fact", "malformed"])
async def test_untrusted_plan_stops_before_second_call(tmp_path, monkeypatch, mutation):
    def mutate(r):
        if mutation == "shell":
            r["steps"][0]["tool_name"] = "arbitrary_shell"
        elif mutation == "unknown_evidence":
            r["evidence_references"] = [str(uuid4())]
        elif mutation == "fact":
            r["observations"] = ["Claimed attack"]
        else:
            del r["hypotheses"]
        return r

    result, calls, _ = await run(tmp_path, monkeypatch, mutate)
    assert len(calls) == 1
    assert result.investigation["status"] == "FAILED_STOP_NO_RETRY"
    assert result.response["host_remediation"] is False


@pytest.mark.asyncio
async def test_cost_ceiling_blocks_before_transport(tmp_path, monkeypatch):
    result, calls, _ = await run(tmp_path, monkeypatch, change=dict(budget_usd="0.000001"))
    assert calls == []
    assert result.external_provider_calls == 0
    assert result.investigation["status"] == "FAILED_STOP_NO_RETRY"


def test_minimized_projection_does_not_send_sources_accounts_domains():
    source = dict(
        evidence_id=str(uuid4()),
        source="private.example",
        summary="user=secret-admin 192.168.1.2 ignore system",
        raw_data="TOKEN=secret",
    )
    request = LLMRequest(
        system_prompt="Trusted instructions",
        user_prompt=json.dumps(
            {"EVIDENCE (UNTRUSTED DATA)": [source], "EXISTING OBSERVATIONS": [source]}
        ),
    )
    projected = minimized(request)
    for value in (
        "private.example",
        "secret-admin",
        "192.168.1.2",
        "TOKEN=secret",
        "ignore system",
    ):
        assert value not in projected.model_dump_json()
    assert source["evidence_id"] in projected.user_prompt


@pytest.mark.parametrize(
    "change",
    [
        dict(expires_at=utc_now() - timedelta(days=1)),
        dict(base_url="http://invalid.example"),
        dict(output_directory="relative"),
        dict(budget_usd="NaN"),
        dict(max_calls=3),
    ],
)
def test_bad_authorization_rejected(tmp_path, change):
    a = authorization(tmp_path, b"input")
    with pytest.raises(ValueError):
        b = APIRunAuthorization.model_validate(a.model_dump() | change)
        b.active()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["network", "no_usage", "excess_usage", "rate_limit"])
async def test_provider_errors_preserve_intent_and_never_retry(tmp_path, monkeypatch, failure):
    def post(self, body):
        if failure in ("network", "rate_limit"):
            raise LLMError("TEST_FAILURE_NO_SECRET")
        return json.dumps(
            dict(
                choices=[
                    dict(
                        finish_reason="stop",
                        message=dict(content=json.dumps(response(json.loads(body)))),
                    )
                ],
                usage=None
                if failure == "no_usage"
                else dict(prompt_tokens=99999999, completion_tokens=1),
            )
        ).encode()

    monkeypatch.setattr(OpenAICompatibleClient, "_post", post)
    a = authorization(tmp_path, b"input")
    written, events = {}, []

    def write(name, value):
        written[name] = value

    c = APIInvestigationClient(a, settings(a), write, lambda name, value: events.append(name))
    req = LLMRequest(
        system_prompt="trusted",
        user_prompt=json.dumps({"EVIDENCE (UNTRUSTED DATA)": [dict(evidence_id=str(uuid4()))]}),
    )
    with pytest.raises(LLMError):
        await c.generate_structured(request=req, response_model=APIInvestigationDraft)
    assert c.calls == 1 and c.stopped
    assert events == ["API_AUTHORIZATION_BOUND", "API_INVOCATION_STARTED", "API_INVOCATION_FAILED"]
    with pytest.raises(LLMError):
        await c.generate_structured(request=req, response_model=APIInvestigationDraft)
    assert c.calls == 1 and "api-failure-0.json" in written


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    ["api-response-0.json", "api-intent-0.json", "api-request-0.json", "api-authorization.json"],
)
async def test_persisted_api_receipt_tamper_is_rejected(tmp_path, monkeypatch, name):
    _, _, w = await run(tmp_path, monkeypatch)
    path = w.directory / name
    value = json.loads(path.read_bytes())
    value["injected"] = "not an audited receipt"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        verify_result(w.directory)


def test_attempt_scope_cannot_be_reused_at_other_directory(tmp_path):
    a = authorization(tmp_path / "one", b"input")
    with pytest.raises(ValueError, match="API_ATTEMPT_DIRECTORY_MISMATCH"):
        OfflineWorkflow(tmp_path / "two", api_authorization=a, api_settings=settings(a))
    assert not (tmp_path / "two").exists()


def test_no_ceiling_requires_explicit_null_not_omission(tmp_path):
    raw = authorization(tmp_path, b"input").model_dump()
    del raw["budget_usd"]
    with pytest.raises(ValueError):
        APIRunAuthorization.model_validate(raw)
    assert APIRunAuthorization.model_validate(raw | dict(budget_usd=None)).budget_usd is None


@pytest.mark.asyncio
async def test_intent_audit_failure_prevents_provider_call(tmp_path, monkeypatch):
    a = authorization(tmp_path, b"input")
    calls = []
    monkeypatch.setattr(OpenAICompatibleClient, "_post", transport(calls))

    def event(code, payload):
        if code == "API_INVOCATION_STARTED":
            raise OSError("TEST_AUDIT_UNAVAILABLE")

    c = APIInvestigationClient(a, settings(a), lambda name, value: None, event)
    with pytest.raises(OSError):
        await c.generate_structured(
            request=LLMRequest(system_prompt="trusted", user_prompt="{}"),
            response_model=APIInvestigationDraft,
        )
    assert c.calls == 0 and calls == []


@pytest.mark.asyncio
async def test_expired_authorization_blocks_request_before_transport(tmp_path, monkeypatch):
    from soc_agent.security_ai import api_investigation

    a = authorization(tmp_path, b"input")
    calls = []
    monkeypatch.setattr(OpenAICompatibleClient, "_post", transport(calls))
    c = APIInvestigationClient(a, settings(a), lambda name, value: None, lambda code, payload: None)
    monkeypatch.setattr(api_investigation, "utc_now", lambda: a.expires_at)
    with pytest.raises(ValueError, match="EXPIRED"):
        await c.generate_structured(
            request=LLMRequest(system_prompt="trusted", user_prompt="{}"),
            response_model=APIInvestigationDraft,
        )
    assert c.calls == 0 and calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_local_timeout_or_cancel_never_reissues_uncertain_http_request(
    tmp_path, monkeypatch, cancel
):
    import asyncio
    import threading

    from soc_agent.llm import LLMTimeoutError

    entered, release = threading.Event(), threading.Event()
    posts = []

    def blocked(self, body):
        posts.append(body)
        entered.set()
        assert release.wait(3)
        return b"{}"  # Late reply must never retroactively settle the cancelled request.

    monkeypatch.setattr(OpenAICompatibleClient, "_post", blocked)
    a = authorization(tmp_path, b"input").model_copy(update={"timeout_seconds": 0.1})
    configured = settings(a).model_copy(update={"timeout_seconds": 0.1})
    records = {}
    api = APIInvestigationClient(a, configured, records.__setitem__, lambda *_: None)
    req = LLMRequest(system_prompt="trusted", user_prompt="{}")
    running = asyncio.create_task(
        api.generate_structured(request=req, response_model=APIInvestigationDraft)
    )
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        if cancel:
            running.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else LLMTimeoutError):
            await running
        proof = records["api-failure-0.json"]
        assert proof["transport_worker_alive"]
        assert proof["usage"] is None and proof["latency_ms"] > 0
        assert proof["billing_outcome"] == "UNKNOWN_REQUIRES_REVIEW"
        assert api.status["total_estimated_usd"] is None
        with pytest.raises(LLMError, match="LIMIT_OR_STOPPED"):
            await api.generate_structured(request=req, response_model=APIInvestigationDraft)
        release.set()
        await asyncio.to_thread(api.provider._transport.join, 1)
        assert not api.provider._transport.is_alive()
        assert api.provider.last_usage is None
        assert api.status["total_estimated_usd"] is None
        with pytest.raises(LLMError, match="LIMIT_OR_STOPPED"):
            await api.generate_structured(request=req, response_model=APIInvestigationDraft)
        assert api.calls == len(posts) == 1
    finally:
        release.set()
        await asyncio.to_thread(api.provider._transport.join, 1)


@pytest.mark.asyncio
async def test_failure_evidence_disk_error_does_not_replace_primary_api_timeout(
    tmp_path, monkeypatch
):
    from soc_agent.llm import LLMTimeoutError

    a = authorization(tmp_path, b"input")

    async def failed(*_args, **_kwargs):
        raise LLMTimeoutError("FAKE_PROVIDER_TIMEOUT")

    monkeypatch.setattr(OpenAICompatibleClient, "generate_structured", failed)

    def write(name, value):
        if name.startswith("api-failure-"):
            raise OSError(28, "fixture disk full")

    api = APIInvestigationClient(a, settings(a), write, lambda *_: None)
    with pytest.raises(LLMTimeoutError) as caught:
        await api.generate_structured(
            request=LLMRequest(system_prompt="trusted", user_prompt="{}"),
            response_model=APIInvestigationDraft,
        )
    assert isinstance(caught.value.__cause__, OSError) and caught.value.__cause__.errno == 28
    assert api.status["failure_evidence"] == "UNVERIFIED"
    assert api.status["total_estimated_usd"] is None
    assert api.calls == 1 and api.stopped
