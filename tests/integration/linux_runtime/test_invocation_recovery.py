"""Actual ledger/guards with fixture LLMs; owned child crashes never call a provider."""

import asyncio
import json
import multiprocessing
import os
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.linux_runtime.findings import correlate
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import BudgetClient, LinuxMonitor
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.llm.errors import LLMTimeoutError
from soc_agent.llm.models import LLMRequest
from soc_agent.planning.models import LLMInvestigationPlanDraft
from soc_agent.runtime_lock import exclusive_runtime_lock


class FixtureClient:
    """Clearly marked fixture assessment; correct evidence IDs come from the real prompt."""

    last_usage = {"prompt_tokens": 7, "completion_tokens": 3}

    def __init__(self, incident_id):
        self.incident_id, self.calls = incident_id, 0

    async def generate_structured(self, *, request, response_model):
        self.calls += 1
        if issubclass(response_model, LLMInvestigationPlanDraft):
            value = {
                "goal": "Fixture READ investigation",
                "steps": [
                    {
                        "tool_name": "read_authentication_context",
                        "tool_input": {"incident_id": str(self.incident_id)},
                        "purpose": "Read retained fixture sources",
                    }
                ],
            }
        else:
            evidence = json.loads(request.user_prompt)["EVIDENCE (UNTRUSTED DATA)"]
            value = {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": "info",
                    "confidence": 0.0,
                    "summary": "Fixture only",
                    "supporting_evidence_ids": [e["evidence_id"] for e in evidence],
                },
            }
        return response_model.model_validate(value)


def seed(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="REAL_LLM")
    monitor.pipeline.collect(monitor.collector)
    for _ in range(3):
        monitor.pipeline.step()
    finding = correlate(monitor.pipeline, monitor.config)[0]
    monitor.store.put(finding)
    monitor.client = FixtureClient(monitor.config.incident_id)
    return root, monitor, finding


def rows(store):
    with store.database.transaction(write=False) as c:
        return [dict(r) for r in c.execute("SELECT * FROM monitor_findings")]


def audits(store):
    with store.database.transaction(write=False) as c:
        return [json.loads(r[0]) for r in c.execute("SELECT payload FROM monitor_audit")]


@pytest.mark.asyncio
async def test_scripted_default_has_no_provider_and_explicit_mode(tmp_path, monkeypatch):
    assert RuntimeConfig.model_fields["assessment_mode"].default == "SCRIPTED"
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="SCRIPTED")
    monitor.client = FixtureClient(monitor.config.incident_id)
    await monitor.tick()
    await monitor.investigate_one()
    assert monitor.store.jobs() == {"DONE_SCRIPTED": 2}
    assert monitor.client.calls == 0
    for row in rows(RuntimeStore(root)):
        result = json.loads(row["result"])
        assert result["mode"] == "SCRIPTED"
        assert result["llm_calls"] == 0
        assert result["write_disposition"] == "WRITE_DENIED"


@pytest.mark.asyncio
async def test_known_usage_atomic_result_and_completed_replay(tmp_path, monkeypatch):
    root, monitor, finding = seed(tmp_path, monkeypatch)
    await monitor.investigate_one()
    first = rows(monitor.store)[0]
    assert first["status"] == "DONE"
    result = json.loads(first["result"])
    assert result["token_usage"] == [FixtureClient.last_usage] * 2
    assert result["cost_estimate"] is None
    assert result["llm_calls"] == 2
    events = audits(monitor.store)
    assert sum(e["kind"] == "LLM_INVOCATION_STARTED" for e in events) == 2
    assert sum(e["kind"] == "LLM_RESPONSE_RECEIVED" for e in events) == 2
    assert not monitor.store.put(finding)
    restarted = LinuxMonitor(root, llm_client=FixtureClient(monitor.config.incident_id))
    restarted.store.recover()
    await restarted.investigate_one()
    assert restarted.client.calls == 0
    assert rows(restarted.store)[0] == first
    assert (await security_check(restarted.pipeline))["write_spy_calls"] == 0


@pytest.mark.asyncio
async def test_intent_audit_failure_prevents_provider_call(tmp_path, monkeypatch):
    _, monitor, finding = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    client = BudgetClient(
        monitor.client, monitor.config, store=monitor.store, finding=finding, attempt=1
    )

    def fault(*args):
        raise OSError("fixture audit unavailable")

    monkeypatch.setattr(monitor.store, "_audit", fault)
    with pytest.raises(OSError):
        await client.generate_structured(
            request=LLMRequest(system_prompt="fixture", user_prompt="fixture"),
            response_model=LLMInvestigationPlanDraft,
        )
    assert monitor.client.calls == client.calls == 0
    assert not any(e["kind"] == "LLM_INVOCATION_STARTED" for e in audits(monitor.store))


def test_recovery_rejects_tampering_before_restamping(tmp_path, monkeypatch):
    _, monitor, _ = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_findings SET attempts=99")
    with pytest.raises(ValueError, match="STATE_INTEGRITY"):
        monitor.store.recover()
    assert rows(monitor.store)[0]["status"] == "RUNNING"


def test_invocation_binding_and_attempt_are_verified(tmp_path, monkeypatch):
    _, monitor, finding = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    with pytest.raises(ValueError, match="ATTEMPT_REJECTED"):
        monitor.store.invocation_event(finding, 2, "LLM_INVOCATION_STARTED", {})
    other = finding.model_copy(update={"incident_id": uuid4()})
    with pytest.raises(ValueError, match="BINDING_REJECTED"):
        monitor.store.invocation_event(other, 1, "LLM_INVOCATION_STARTED", {})


@pytest.mark.asyncio
async def test_unknown_timeout_is_not_retried_or_completed(tmp_path, monkeypatch):
    root, monitor, _ = seed(tmp_path, monkeypatch)

    class TimeoutClient:
        calls = 0

        async def generate_structured(self, **kwargs):
            self.calls += 1
            raise LLMTimeoutError("fixture provider timeout")

    monitor.client = TimeoutClient()
    await monitor.investigate_one()
    result = json.loads(rows(monitor.store)[0]["result"])
    assert monitor.store.jobs() == {"FAILED": 1}
    assert result["invocation_outcome"] == "UNKNOWN"
    assert result["token_usage"] == [None]
    restored = LinuxMonitor(root, llm_client=monitor.client)
    await restored.investigate_one()
    assert monitor.client.calls == 1
    assert any(e["kind"] == "LLM_INVOCATION_FAILED" for e in audits(restored.store))


POINTS = ("FINDING_COMMIT", "BEFORE_CALL", "AFTER_RESPONSE", "BEFORE_RESULT", "AFTER_RESULT")


def crash_child(directory, point, channel, nonce):
    root = Path(directory)
    with exclusive_runtime_lock(root / "writer.lock"):
        monitor = LinuxMonitor(root)
        monitor.client = FixtureClient(monitor.config.incident_id)

        def pause():
            channel.send((os.getpid(), nonce, point))
            channel.recv()

        if point == "FINDING_COMMIT":
            pause()
        invocation = monitor.store.invocation_event
        finish = monitor.store.finish

        def event_hook(finding, attempt, kind, details):
            invocation(finding, attempt, kind, details)
            if (point == "BEFORE_CALL" and kind == "LLM_INVOCATION_STARTED") or (
                point == "AFTER_RESPONSE" and kind == "LLM_RESPONSE_RECEIVED"
            ):
                pause()

        def finish_hook(*args, **kwargs):
            if point == "BEFORE_RESULT":
                pause()
            finish(*args, **kwargs)
            if point == "AFTER_RESULT":
                pause()

        monitor.store.invocation_event = event_hook
        monitor.store.finish = finish_hook
        asyncio.run(monitor.investigate_one())


@pytest.mark.parametrize("point", POINTS)
def test_owned_crash_invocation_uncertainty_and_atomic_result(tmp_path, monkeypatch, point):
    root, monitor, finding = seed(tmp_path, monkeypatch)
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe(duplex=True)
    nonce = str(uuid4())
    process = context.Process(target=crash_child, args=(str(root), point, sender, nonce))
    process.start()
    sender.close()
    try:
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        restored = RuntimeStore(root)
        with exclusive_runtime_lock(root / "writer.lock"):
            restored.recover()
            expected = (
                "DONE"
                if point == "AFTER_RESULT"
                else ("PENDING" if point == "FINDING_COMMIT" else "BLOCKED")
            )
            assert restored.jobs() == {expected: 1}
            if expected == "BLOCKED":
                assert restored.claim() is None
                assert json.loads(rows(restored)[0]["result"])["invocation_outcome"] == "UNKNOWN"
            if expected == "DONE":
                events = audits(restored)
                assert any(
                    e["kind"] == "INVESTIGATION_DONE"
                    and e["details"]["result_digest"] == rows(restored)[0]["result_digest"]
                    for e in events
                )
            for database in (
                restored.database,
                monitor.pipeline.queue.database,
                monitor.pipeline.store.database,
            ):
                with database.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert not restored.put(finding)
            restored.verify_audit()
            assert asyncio.run(security_check(monitor.pipeline))["write_spy_calls"] == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()


@pytest.mark.parametrize(
    "attack", ["WRITE_TOOL", "UNKNOWN_TOOL", "OTHER_INCIDENT", "FORGED_EVIDENCE"]
)
@pytest.mark.asyncio
async def test_untrusted_llm_cannot_escalate_or_forge_evidence(tmp_path, monkeypatch, attack):
    _, monitor, _ = seed(tmp_path, monkeypatch)
    client = monitor.client
    original = client.generate_structured

    async def malicious(*, request, response_model):
        result = await original(request=request, response_model=response_model)
        if issubclass(response_model, LLMInvestigationPlanDraft):
            if attack in ("WRITE_TOOL", "UNKNOWN_TOOL"):
                payload = result.model_dump()
                payload["steps"][0]["tool_name"] = (
                    "disable_account" if attack == "WRITE_TOOL" else "arbitrary_shell"
                )
                return response_model.model_validate(payload)
            if attack == "OTHER_INCIDENT":
                payload = result.model_dump()
                payload["steps"][0]["tool_input"] = {"incident_id": str(uuid4())}
                return response_model.model_validate(payload)
        elif attack == "FORGED_EVIDENCE":
            payload = result.model_dump(mode="json")
            payload["assessment"]["supporting_evidence_ids"] = [str(uuid4())]
            return response_model.model_validate(payload)
        return result

    client.generate_structured = malicious
    await monitor.investigate_one()
    assert monitor.store.jobs() == {"FAILED": 1}
    result = json.loads(rows(monitor.store)[0]["result"])
    assert result["write_disposition"] == "WRITE_DENIED"
    assert "assessment" not in result
    assert (await security_check(monitor.pipeline))["write_spy_calls"] == 0


@pytest.mark.asyncio
async def test_result_commit_failure_retains_sources_and_blocks_replay(tmp_path, monkeypatch):
    import sqlite3

    root, monitor, _ = seed(tmp_path, monkeypatch)
    original_finish = monitor.store.finish
    original_commit = monitor.store.database._commit

    def fail_commit(connection):
        raise sqlite3.OperationalError("fixture disk write failure")

    def broken_finish(*args, **kwargs):
        monkeypatch.setattr(monitor.store.database, "_commit", fail_commit)
        return original_finish(*args, **kwargs)

    monkeypatch.setattr(monitor.store, "finish", broken_finish)
    from soc_agent.review.persistence.models import StorageError

    with pytest.raises(StorageError):
        await monitor.investigate_one()
    monkeypatch.setattr(monitor.store.database, "_commit", original_commit)
    restored = RuntimeStore(root)
    assert restored.jobs() == {"RUNNING": 1}
    assert rows(restored)[0]["result"] is None
    assert not any(e["kind"] == "INVESTIGATION_DONE" for e in audits(restored))
    restored.recover()
    assert restored.jobs() == {"BLOCKED": 1}
    assert (await security_check(monitor.pipeline))["write_spy_calls"] == 0


@pytest.mark.asyncio
async def test_timeout_disables_configured_retries_for_unknown_invocation(tmp_path, monkeypatch):
    _, monitor = setup(
        tmp_path, monkeypatch, assessment_mode="REAL_LLM", investigation_retry_limit=3
    )
    monitor.pipeline.collect(monitor.collector)
    for _ in range(3):
        monitor.pipeline.step()
    monitor.store.put(correlate(monitor.pipeline, monitor.config)[0])

    class TimeoutClient:
        calls = 0

        async def generate_structured(self, **kwargs):
            self.calls += 1
            raise LLMTimeoutError("fixture timeout")

    monitor.client = TimeoutClient()
    await monitor.investigate_one()
    await monitor.investigate_one()
    assert monitor.store.jobs() == {"FAILED": 1}
    assert monitor.client.calls == 1


@pytest.mark.asyncio
async def test_planner_receives_runtime_limit_in_prompt_and_schema(tmp_path, monkeypatch):
    _, monitor, _ = seed(tmp_path, monkeypatch)
    client = monitor.client
    original = client.generate_structured
    observed = []

    async def inspect(*, request, response_model):
        if issubclass(response_model, LLMInvestigationPlanDraft):
            observed.append(response_model.model_json_schema()["properties"]["steps"]["maxItems"])
            assert "1 to 2 steps" in request.system_prompt
            from pydantic import ValidationError

            draft = await original(request=request, response_model=response_model)
            payload = draft.model_dump()
            payload["steps"] *= 3
            with pytest.raises(ValidationError):
                response_model.model_validate(payload)
            return draft
        return await original(request=request, response_model=response_model)

    client.generate_structured = inspect
    await monitor.investigate_one()
    assert observed == [2]
    assert monitor.store.jobs() == {"DONE": 1}


def test_completion_cannot_repair_tampered_job_or_result_binding(tmp_path, monkeypatch):
    _, monitor, finding = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    with pytest.raises(ValueError, match="RESULT_BINDING_MISMATCH"):
        monitor.store.finish(finding, "DONE", {"finding_digest": "0" * 64})
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_findings SET attempts=98")
    with pytest.raises(ValueError, match="STATE_INTEGRITY"):
        monitor.store.finish(finding, "DONE", {"finding_digest": finding.digest})
    assert rows(monitor.store)[0]["status"] == "RUNNING"


def test_restart_validates_completed_result_receipt_before_accepting_work(tmp_path, monkeypatch):
    _, monitor, finding = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    monitor.store.finish(finding, "DONE", {"finding_digest": finding.digest})
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_findings SET result='{}'")
    with pytest.raises(ValueError, match="RESULT_INTEGRITY"):
        monitor.store.recover()


def test_blocked_recovery_cannot_report_ready_with_previous_success(tmp_path, monkeypatch):
    from soc_agent.linux_runtime.__main__ import status
    from soc_agent.state.evidence import utc_now

    root, monitor, _ = seed(tmp_path, monkeypatch)
    monitor.store.claim()
    monitor.store.update(
        state="RUNNING",
        collector="RESUMED_EXACT",
        llm="AVAILABLE",
        started_at=utc_now().isoformat(),
        last_error=None,
    )
    monitor.store.recover()
    output = status(root)
    assert output["blocked_investigations"] == 1
    assert output["readiness"] == "NOT_READY"
    assert output["health"] == "DEGRADED"
