"""Actual guards/socket/SQLite with explicitly injected fixture failures, no live API."""

import json
import os
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from tests.integration.linux_runtime.test_monitor import setup
from tests.unit.holdout.test_contract import contracts, reseal
from tests.unit.operational_features.test_native_authentication import START, row

from soc_agent.experience.failure import FailureQuery, capture_failure
from soc_agent.improvement_review.models import ReviewDecision
from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop, FailureFeedbackRequest
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop
from soc_agent.linux_runtime.feedback_projection import project_feedback
from soc_agent.linux_runtime.holdout_evaluation import HoldoutEvaluation
from soc_agent.linux_runtime.operator import OperatorRequest, OperatorServer, operator_request
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.llm.errors import LLMResponseValidationError, LLMTimeoutError
from soc_agent.llm.openai_compatible import LLMNetworkError, LLMProviderError
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational import authentication_investigation as auth
from soc_agent.tools import ToolRegistry


@asynccontextmanager
async def prepared(tmp_path, monkeypatch, *, kind="SUSPECTED_MISS", error_type=LLMTimeoutError):
    if kind == "SUSPECTED_MISS":
        records = [row(1, 1, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")]
        root, monitor = setup(tmp_path, monkeypatch, records=records)
        await monitor.tick()
        with monitor.pipeline.store.database.transaction(write=False) as c:
            refs = tuple(
                monitor.pipeline.store._decode(r).header.event_id
                for r in c.execute("SELECT * FROM operational_sources")
            )
        query = FailureQuery(
            kind=kind,
            incident_id=monitor.config.incident_id,
            event_references=refs,
            expected_rule="REPEATED_AUTH_FAILURE",
            window_start=START,
            window_end=START + timedelta(minutes=5),
        )
    else:
        mode = "REAL_LLM" if kind == "LLM_FAILURE" else "READ_ONLY"
        root, monitor = setup(
            tmp_path, monkeypatch, assessment_mode=mode, investigation_retry_limit=0
        )
        if kind == "LLM_FAILURE":

            class Client:
                async def generate_structured(self, **kwargs):
                    raise error_type("PRIVATE_ERROR_SECRET fixture only")

            monitor.client = Client()
        elif kind == "TOOL_FAILURE":
            original = auth.authentication_read_registry

            def registry(pipeline):
                result = original(pipeline)

                async def failing_read(value):
                    raise OSError("PRIVATE_TOOL_SECRET fixture only")

                # Only the READ handler is replaced. Actual registry/Tool/guard/orchestrator run.
                tool = replace(result.get("read_authentication_context"), handler=failing_read)
                registry = ToolRegistry()
                registry.execution_guard = auth.AuthenticationReadGuard(pipeline.incident_id)
                registry.register(tool)
                return registry

            monkeypatch.setattr(auth, "authentication_read_registry", registry)
        await monitor.tick()
        await monitor.investigate_one()
        with monitor.store.database.transaction(write=False) as c:
            identity = c.execute(
                "SELECT id FROM monitor_findings WHERE status IN ('FAILED','BLOCKED')"
            ).fetchone()[0]
        query = FailureQuery(kind=kind, incident_id=monitor.config.incident_id, finding_id=identity)
    server = OperatorServer(monitor, (os.geteuid(),))
    with exclusive_runtime_lock(root / "writer.lock"):
        await server.start()
        try:
            yield root, monitor, query
        finally:
            await server.close()


async def submit(root, monitor, query, **kwargs):
    experience = capture_failure(monitor, query)
    request = FailureFeedbackRequest(
        feedback_id=kwargs.pop("feedback_id", uuid4()),
        query=query,
        expected_experience_id=experience["experience_id"],
        reason_code="EXPECTED_RULE_MISSING"
        if query.kind == "SUSPECTED_MISS"
        else "OBSERVED_RUNTIME_FAILURE",
        **kwargs,
    )
    response = await operator_request(root, "failure-submit", failure_feedback=request)
    return response, request


@pytest.mark.asyncio
async def test_suspected_miss_without_finding_idempotency_correction_and_restart(
    tmp_path, monkeypatch
):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        assert not monitor.store.jobs()
        experience = await operator_request(root, "failure-experience", failure_query=query)
        assert (
            experience["ok"]
            and experience["result"]["label_assurance"] == "NO_INDEPENDENT_GROUND_TRUTH"
        )
        response, request = await submit(root, monitor, query)
        assert response["ok"]
        assert response["result"]["reviewer_uid"] == os.geteuid()
        assert (await operator_request(root, "failure-submit", failure_feedback=request))[
            "result"
        ] == response["result"]
        assert not (
            await operator_request(
                root,
                "failure-submit",
                failure_feedback=request.model_copy(update={"reason_code": "INSUFFICIENT_CONTEXT"}),
            )
        )["ok"]
        corrected, _ = await submit(root, monitor, query, supersedes=request.feedback_id)
        assert corrected["ok"]
        values = (await operator_request(root, "candidates"))["result"]["candidates"]
        assert len(values) == 1
        assert values[0]["content"]["schema_version"] == "improvement-candidate:v4"
        assert values[0]["content"]["proposal"]["category"] == "MISSED_DETECTION_REVIEW"
        assert len(values[0]["content"]["supporting_sample_refs"]) == 1
        assert (await operator_request(root, "candidates"))["result"]["candidates"] == values
        projected = project_feedback(monitor)
        assert len(projected["failure_feedback"]) == 2
        assert projected["ground_truth_generation"] == "DISABLED"
        assert projected["write_disposition"] == "WRITE_DENIED"
    restored = FailureFeedbackLoop(LinuxMonitor(root))
    assert len(restored.records()) == 2 and len(restored.active()) == 1
    assert len(restored.candidates()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type,category",
    [
        (LLMTimeoutError, "TIMEOUT"),
        (LLMNetworkError, "NETWORK_ERROR"),
        (LLMProviderError, "PROVIDER_ERROR"),
        (LLMResponseValidationError, "RESPONSE_VALIDATION_ERROR"),
    ],
)
async def test_actual_llm_failure_receipt_sanitized_and_bound(
    tmp_path, monkeypatch, error_type, category
):
    async with prepared(tmp_path, monkeypatch, kind="LLM_FAILURE", error_type=error_type) as (
        root,
        monitor,
        query,
    ):
        experience = capture_failure(monitor, query)
        assert experience["category"] == category
        assert experience["failure_audit_reference"]
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        assert candidate["content"]["proposal"]["category"] == "LLM_RELIABILITY_REVIEW"
        with pytest.raises(ValueError):
            capture_failure(monitor, query.model_copy(update={"kind": "TOOL_FAILURE"}))
        with monitor.store.database.transaction(write=False) as c:
            text = "".join(r[0] for r in c.execute("SELECT payload FROM monitor_audit"))
        assert "PRIVATE_ERROR_SECRET" not in text
    assert len(FailureFeedbackLoop(LinuxMonitor(root)).active()) == 1


@pytest.mark.asyncio
async def test_actual_read_handler_failure_receipt_and_llm_misclassification_denied(
    tmp_path, monkeypatch
):
    async with prepared(tmp_path, monkeypatch, kind="TOOL_FAILURE") as (root, monitor, query):
        experience = capture_failure(monitor, query)
        assert experience["category"] == "TOOL_ERROR"
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        assert candidate["content"]["proposal"]["category"] == "TOOL_RELIABILITY_REVIEW"
        with pytest.raises(ValueError):
            capture_failure(monitor, query.model_copy(update={"kind": "LLM_FAILURE"}))
        with monitor.store.database.transaction(write=False) as c:
            text = "".join(r[0] for r in c.execute("SELECT payload FROM monitor_audit"))
        assert "PRIVATE_TOOL_SECRET" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack", ["incident", "source", "label", "time", "digest", "actor", "replay"]
)
async def test_feedback_source_and_identity_forgeries(tmp_path, monkeypatch, attack):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        if attack in ("incident", "source", "label", "time"):
            change = {
                "incident": {"incident_id": uuid4()},
                "source": {"event_references": ("forged",)},
                "label": {"independent_label_reference": "0" * 64},
                "time": {"window_end": START + timedelta(seconds=1)},
            }[attack]
            assert not (
                await operator_request(
                    root, "failure-experience", failure_query=query.model_copy(update=change)
                )
            )["ok"]
        else:
            experience = capture_failure(monitor, query)
            request = FailureFeedbackRequest(
                feedback_id=uuid4(),
                query=query,
                expected_experience_id=experience["experience_id"],
                reason_code="EXPECTED_RULE_MISSING",
            )
            if attack == "digest":
                assert not (
                    await operator_request(
                        root,
                        "failure-submit",
                        failure_feedback=request.model_copy(
                            update={"expected_experience_id": "0" * 64}
                        ),
                    )
                )["ok"]
            elif attack == "actor":
                body = request.model_dump(mode="json") | {"reviewer_uid": os.geteuid()}
                with pytest.raises(ValueError):
                    FailureFeedbackRequest.model_validate_json(json.dumps(body))
            else:
                nonce = uuid4()
                assert (
                    await operator_request(
                        root, "failure-submit", failure_feedback=request, request_id=nonce
                    )
                )["ok"]
                assert not (
                    await operator_request(
                        root, "failure-submit", failure_feedback=request, request_id=nonce
                    )
                )["ok"]


@pytest.mark.asyncio
async def test_failure_feedback_audit_failure_atomic_and_source_tamper(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        original = monitor.store._audit

        def fault(c, kind, details):
            if kind == "FAILURE_FEEDBACK":
                raise OSError("fixture disk write failure")
            return original(c, kind, details)

        monkeypatch.setattr(monitor.store, "_audit", fault)
        assert not (await submit(root, monitor, query))[0]["ok"]
        monkeypatch.setattr(monitor.store, "_audit", original)
        assert not FailureFeedbackLoop(monitor).records()
        assert (await submit(root, monitor, query))[0]["ok"]
        with monitor.pipeline.store.database.transaction() as c:
            c.execute("UPDATE operational_sources SET digest='tampered'")
        with pytest.raises(ValueError):
            FailureFeedbackLoop(monitor).active()
        with pytest.raises(ValueError):
            project_feedback(monitor)


@pytest.mark.asyncio
async def test_failure_candidate_blocked_reliability_evaluation_and_human_review(
    tmp_path, monkeypatch
):
    async with prepared(tmp_path, monkeypatch, kind="LLM_FAILURE") as (root, monitor, query):
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        loop = RuntimeFeedbackLoop(monitor)
        evaluation = loop.evaluate(
            candidate["candidate_id"], repeated_failures=4, multiple_accounts=4
        )
        assert evaluation["verdict"] == "BLOCKED" and all(
            v is None for v in evaluation["metrics"].values()
        )
        base = dict(
            candidate_id=candidate["candidate_id"], expected_evaluation=evaluation["evaluation_id"]
        )
        assert not (
            await operator_request(
                root, "candidate-review", review_decision=ReviewDecision.APPROVE, **base
            )
        )["ok"]
        result = await operator_request(
            root, "candidate-review", review_decision=ReviewDecision.DEFER, **base
        )
        assert result["ok"] and result["result"]["status"] == "INCONCLUSIVE"
        assert result["result"]["promotion"] == "BLOCKED"
        assert monitor.config.assessment_mode == "REAL_LLM"


@pytest.mark.asyncio
async def test_paired_disjoint_fixture_trial_one_use_and_regression(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        dataset, contract = contracts()
        evaluation = HoldoutEvaluation(monitor).run(
            candidate["candidate_id"], contract, dataset, repeated_failures=6, multiple_accounts=3
        )
        assert evaluation["scope"] == "DECLARED_DISJOINT_FIXTURE_ONLY_NOT_OPERATING_HOLDOUT"
        assert evaluation["baseline"]["confusion_matrix"]["FN"] == 0
        assert evaluation["trial"]["confusion_matrix"]["FN"] == 2
        assert evaluation["regression_gate"] == "REGRESSED"
        assert evaluation["verdict"] == "INCONCLUSIVE" and evaluation["promotion"] == "BLOCKED"
        with pytest.raises(ValueError, match="HOLDOUT_REUSE"):
            HoldoutEvaluation(monitor).run(
                candidate["candidate_id"],
                contract,
                dataset,
                repeated_failures=3,
                multiple_accounts=3,
            )
        # Operator opinion cannot turn a fixture/unknown source into operating verified truth.
        body = contract.model_dump(mode="json")
        body["source_assurance"] = "EXTERNAL_REPORTED"
        result = HoldoutEvaluation(monitor).run(
            candidate["candidate_id"],
            reseal(body),
            dataset,
            repeated_failures=3,
            multiple_accounts=3,
        )
        assert result["verdict"] == "BLOCKED" and result["metrics"] is None


def test_operator_body_cannot_supply_reviewer_identity():
    body = {
        "request_id": str(uuid4()),
        "challenge": str(uuid4()),
        "created_at": START.isoformat(),
        "command": "failure-list",
        "actor": "admin",
    }
    with pytest.raises(ValueError):
        OperatorRequest.model_validate_json(json.dumps(body))


@pytest.mark.asyncio
async def test_pam_module_is_not_final_login_miss_and_present_rule_is_not_fn(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch, kind="TOOL_FAILURE") as (_, monitor, query):
        with monitor.store.database.transaction(write=False) as c:
            finding = monitor.store._decode(
                c.execute(
                    "SELECT * FROM monitor_findings WHERE id=?", (query.finding_id,)
                ).fetchone()
            )
        miss = FailureQuery(
            kind="SUSPECTED_MISS",
            incident_id=finding.incident_id,
            event_references=finding.event_references,
            expected_rule=finding.rule_id,
            window_start=START,
            window_end=START + timedelta(minutes=5),
        )
        with pytest.raises(ValueError, match="ALREADY_PRESENT"):
            capture_failure(monitor, miss)
    from soc_agent.demo.scenario_models import PAM

    pam = row(12, 1, PAM)
    pam.update(_EXE="/usr/bin/sudo", _COMM="sudo", _UID="1000")
    root, monitor = setup(tmp_path / "pam", monkeypatch, records=[pam])
    await monitor.tick()
    with monitor.pipeline.store.database.transaction(write=False) as c:
        source = monitor.pipeline.store._decode(
            c.execute("SELECT * FROM operational_sources WHERE status='ACCEPTED'").fetchone()
        )
    miss = FailureQuery(
        kind="SUSPECTED_MISS",
        incident_id=monitor.config.incident_id,
        event_references=(source.header.event_id,),
        expected_rule="REPEATED_AUTH_FAILURE",
        window_start=START,
        window_end=START + timedelta(minutes=5),
    )
    with pytest.raises(ValueError, match="SEMANTICS_MISMATCH"):
        capture_failure(monitor, miss)


@pytest.mark.asyncio
async def test_feedback_digest_and_core_evaluation_adoption_blocked(tmp_path, monkeypatch):
    from soc_agent.linux_runtime.failure_feedback import FailureFeedback
    from soc_agent.offline_evaluation.models import SplitConfig
    from soc_agent.offline_evaluation.planning import specify
    from soc_agent.review.persistence.models import StoredDataError

    async with prepared(tmp_path, monkeypatch, kind="LLM_FAILURE") as (root, monitor, query):
        response, request = await submit(root, monitor, query)
        body = response["result"]
        body["reviewer_uid"] += 1
        with pytest.raises(ValueError):
            FailureFeedback.model_validate_json(json.dumps(body))
        candidates = FailureFeedbackLoop(monitor).prepare_candidates()
        with pytest.raises(StoredDataError):
            specify(candidates[0], (), SplitConfig())
        with pytest.raises(ValueError):
            FailureFeedbackLoop(monitor).submit(request, None)
        # No reliability denominator is fabricated from unrecorded tool attempts.
        observed = FailureFeedbackLoop(monitor).observed_metrics()
        assert observed["failure_rate"] == 1 and observed["timeout_rate"] == 1
        assert observed["tool_call_count"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("point", ["claim", "comparison"])
async def test_holdout_audit_failure_prevents_success_and_reuse(tmp_path, monkeypatch, point):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        dataset, contract = contracts()
        original = monitor.store._audit

        def fault(c, kind, details):
            if kind == ("HOLDOUT_CLAIM" if point == "claim" else "RUNTIME_OFFLINE_EVALUATION"):
                raise OSError("fixture commit failure")
            original(c, kind, details)

        monkeypatch.setattr(monitor.store, "_audit", fault)
        with pytest.raises(OSError):
            HoldoutEvaluation(monitor).run(
                candidate["candidate_id"],
                contract,
                dataset,
                repeated_failures=4,
                multiple_accounts=3,
            )
        monkeypatch.setattr(monitor.store, "_audit", original)
        if point == "comparison":
            with pytest.raises(ValueError, match="HOLDOUT_REUSE"):
                HoldoutEvaluation(monitor).run(
                    candidate["candidate_id"],
                    contract,
                    dataset,
                    repeated_failures=4,
                    multiple_accounts=3,
                )
        else:
            assert (
                HoldoutEvaluation(monitor).run(
                    candidate["candidate_id"],
                    contract,
                    dataset,
                    repeated_failures=4,
                    multiple_accounts=3,
                )["promotion"]
                == "BLOCKED"
            )


@pytest.mark.asyncio
async def test_holdout_reordering_cannot_bypass_consumption(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        assert (await submit(root, monitor, query))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        dataset, contract = contracts()
        evaluator = HoldoutEvaluation(monitor)
        evaluator.run(
            candidate["candidate_id"], contract, dataset, repeated_failures=4, multiple_accounts=3
        )
        from soc_agent.security_ai.external.models import content_digest_payload

        body = contract.model_dump(mode="json")
        body["members"].reverse()
        body["source_digest"] = content_digest_payload(
            {"members": [m["source_digest"] for m in body["members"]]}
        )
        with pytest.raises(ValueError, match="HOLDOUT_REUSE"):
            evaluator.run(
                candidate["candidate_id"],
                reseal(body),
                dataset,
                repeated_failures=3,
                multiple_accounts=3,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["LLM_REQUESTS", "READ_TOOL_CALLS"])
async def test_budget_failure_uses_real_invocation_audit_without_provider_retry(
    tmp_path, monkeypatch, limit
):
    from pydantic import BaseModel

    from soc_agent.linux_runtime.service import BudgetClient

    class Output(BaseModel):
        steps: tuple[int, ...] = ()

    class Client:
        calls = 0

        async def generate_structured(self, **kwargs):
            self.calls += 1
            return Output(steps=(1, 2)) if limit == "READ_TOOL_CALLS" else Output()

    from soc_agent.llm.models import LLMRequest

    root, monitor = setup(tmp_path, monkeypatch, max_llm_calls=2, max_tool_calls=1)
    await monitor.tick()
    finding, attempt = monitor.store.claim()
    client = Client()
    budget = BudgetClient(
        client, monitor.config, store=monitor.store, finding=finding, attempt=attempt
    )
    request = LLMRequest(
        system_prompt="bounded fixture request", user_prompt="bounded fixture data"
    )
    if limit == "LLM_REQUESTS":
        await budget.generate_structured(request=request, response_model=Output)
        await budget.generate_structured(request=request, response_model=Output)
    with pytest.raises(LLMResponseValidationError):
        await budget.generate_structured(request=request, response_model=Output)
    assert client.calls == (2 if limit == "LLM_REQUESTS" else 1)
    monitor.store.finish(
        finding,
        "BLOCKED",
        {
            "finding_digest": finding.digest,
            "failure_code": "INVESTIGATION_FAILURE",
            "write_disposition": "WRITE_DENIED",
        },
    )
    query = FailureQuery(
        kind="LLM_FAILURE", incident_id=monitor.config.incident_id, finding_id=finding.finding_id
    )
    assert capture_failure(monitor, query)["category"] == "BUDGET_EXCEEDED"


@pytest.mark.asyncio
async def test_incomplete_invocation_is_unknown_not_zero_failure_rate(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    await monitor.tick()
    finding, attempt = monitor.store.claim()
    # Fixture crash point: durable request intent but no terminal provider/result receipt.
    monitor.store.invocation_event(
        finding, attempt, "LLM_INVOCATION_STARTED", {"call": 1, "request_digest": "0" * 64}
    )
    metrics = FailureFeedbackLoop(monitor).observed_metrics()
    assert metrics["incomplete_llm_invocations"] == 1
    assert metrics["failure_rate"] is None and metrics["timeout_rate"] is None
    assert metrics["successful_investigation_rate"] is None
    assert metrics["tool_call_count"] is None
