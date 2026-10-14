"""Fixture-driven monitoring through actual SQLite/guards; native smoke is separate."""

import asyncio
from uuid import UUID

import pytest
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.linux_runtime.__main__ import status
from soc_agent.linux_runtime.findings import correlate
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import BudgetClient, LinuxMonitor, initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.llm import MockLLMClient
from soc_agent.llm.errors import LLMResponseValidationError, LLMTimeoutError
from soc_agent.realtime.collectors import CollectorUnavailable, CursorUnavailable
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    project_journal,
)


def setup(tmp_path, monkeypatch, records=None, **config):
    config.setdefault("assessment_mode", "READ_ONLY")
    cfg = RuntimeConfig(
        incident_id=UUID(int=55),
        repeated_failures=3,
        multiple_accounts=3,
        poll_seconds=0.2,
        **config,
    )
    root = tmp_path / "monitor"
    initialize(root, cfg)
    values = records or [
        row(i, i, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")
        for i in range(1, 4)
    ]
    events = [project_journal(r, include_pam_failures=True) for r in values]

    def poll(self, cursor, limit):
        start = next(
            (i + 1 for i, e in enumerate(events) if cursor and e.event_id == cursor.event_id), 0
        )
        return events[start : start + limit]

    monkeypatch.setattr(LinuxAuthenticationCollector, "poll", poll)
    return root, LinuxMonitor(root)


@pytest.mark.asyncio
async def test_continuous_fixture_lifecycle_dedup_resume_and_read_guard(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    await monitor.run(duration_seconds=1.5)
    assert monitor.pipeline.queue.counts() == {"DONE": 3}
    jobs = monitor.store.jobs()
    assert jobs == {"DONE_READ_ONLY": 2}  # Source and account rules, immutable separate hypotheses.
    digest = monitor.store.verify_audit()
    restarted = LinuxMonitor(root)
    await restarted.run(duration_seconds=0.4)
    assert restarted.store.jobs() == jobs
    assert restarted.pipeline.queue.counts() == {"DONE": 3}
    assert restarted.store.verify_audit() != digest
    assert status(root)["readiness"] == "NOT_READY"
    assert status(root)["real_os_handler_calls"] == 0


@pytest.mark.asyncio
async def test_cursor_gap_stops_without_reset_or_loss(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    await monitor.run(duration_seconds=0.2)
    cursor = monitor.pipeline.queue.cursor(monitor.collector.identity)

    def gap(*args):
        raise CursorUnavailable("fixture-gap")

    monkeypatch.setattr(LinuxAuthenticationCollector, "poll", gap)
    failed = LinuxMonitor(root)
    with pytest.raises(ValueError, match="GAP_DETECTED"):
        await failed.run(duration_seconds=0.2)
    assert (
        failed.pipeline.queue.cursor(failed.collector.identity).source_digest
        == cursor.source_digest
    )
    assert failed.store.state()["state"] == "FAILED"


@pytest.mark.asyncio
async def test_collector_bounded_retry(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, collector_retry_limit=1)

    def unavailable(*args):
        raise CollectorUnavailable("fixture-unavailable")

    monkeypatch.setattr(LinuxAuthenticationCollector, "poll", unavailable)
    with pytest.raises(ValueError, match="RETRY_LIMIT"):
        await monitor.run(duration_seconds=3)
    assert monitor.pipeline.queue.counts() == {}
    assert monitor.collection_failures == 2


@pytest.mark.asyncio
async def test_job_ledger_recovery_tamper_and_completion_rollback(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    monitor.pipeline.collect(monitor.collector)
    for _ in range(3):
        monitor.pipeline.step()
    finding = correlate(monitor.pipeline, monitor.config)[0]
    assert monitor.store.put(finding)
    assert not monitor.store.put(finding)
    assert monitor.store.claim()[0] == finding
    restored = RuntimeStore(root)
    restored.recover()
    assert restored.jobs() == {"PENDING": 1}
    restored.claim()
    original = restored._audit

    def fault(*args):
        raise ValueError("FAULT_BEFORE_COMMIT")

    monkeypatch.setattr(restored, "_audit", fault)
    with pytest.raises(ValueError, match="FAULT"):
        restored.finish(finding, "DONE_READ_ONLY", {"finding_digest": finding.digest})
    assert RuntimeStore(root).jobs() == {"RUNNING": 1}
    monkeypatch.setattr(restored, "_audit", original)
    with restored.database.transaction() as c:
        c.execute("UPDATE monitor_findings SET status='DONE'")
    with pytest.raises(ValueError, match="STATE_INTEGRITY"):
        restored.jobs()


@pytest.mark.asyncio
async def test_llm_failure_is_not_mock_success_and_circuit_persists(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="REAL_LLM", circuit_failures=1)

    class Failing:
        async def generate_structured(self, **kwargs):
            raise LLMTimeoutError("Fixture timeout")

    monitor.client = Failing()
    await monitor.run(duration_seconds=1.5)
    assert monitor.store.jobs().get("FAILED") == 1
    assert monitor.circuit_open
    assert LinuxMonitor(root, llm_client=Failing()).circuit_open
    assert status(root)["llm_availability"] == "CIRCUIT_OPEN"


@pytest.mark.asyncio
async def test_stop_during_investigation_retains_unfinished_job(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="REAL_LLM", shutdown_seconds=0.1)
    entered = asyncio.Event()

    class Waiting:
        async def generate_structured(self, **kwargs):
            entered.set()
            await asyncio.Event().wait()

    monitor.client = Waiting()
    task = asyncio.create_task(monitor.run())
    await asyncio.wait_for(entered.wait(), timeout=3)
    monitor.store.request_stop()
    await asyncio.wait_for(task, timeout=3)
    assert monitor.store.state()["state"] == "STOPPED"
    assert monitor.store.jobs()["BLOCKED"] == 1  # External invocation may still be alive.


@pytest.mark.asyncio
async def test_duplicate_runtime_lock_never_recovers_other_worker(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    with exclusive_runtime_lock(root / "writer.lock"):
        with pytest.raises(OSError):
            await monitor.run(duration_seconds=0.2)
    assert monitor.pipeline.queue.counts() == {}


@pytest.mark.asyncio
async def test_budget_checks_tool_and_call_limit_before_execution():
    cfg = RuntimeConfig(
        incident_id=UUID(int=1), repeated_failures=3, multiple_accounts=3, max_tool_calls=1
    )
    llm = MockLLMClient(
        [
            {
                "goal": "read",
                "steps": [
                    {
                        "tool_name": "read_authentication_context",
                        "tool_input": {},
                        "purpose": "fixture",
                    }
                ]
                * 2,
            }
        ]
    )
    from soc_agent.llm.models import LLMRequest
    from soc_agent.planning.models import LLMInvestigationPlanDraft

    client = BudgetClient(llm, cfg)
    with pytest.raises(LLMResponseValidationError, match="TOOL_CALL_LIMIT"):
        await client.generate_structured(
            request=LLMRequest(system_prompt="fixture", user_prompt="fixture"),
            response_model=LLMInvestigationPlanDraft,
        )
    client.calls = 2
    with pytest.raises(LLMResponseValidationError, match="CALL_LIMIT"):
        await client.generate_structured(request=None, response_model=LLMInvestigationPlanDraft)


@pytest.mark.asyncio
async def test_backpressure_drains_pending_without_cursor_loss(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    from soc_agent.realtime.queue import QueueFull

    original = monitor.pipeline.queue.enqueue

    def full(*args, **kwargs):
        raise QueueFull("fixture full")

    monkeypatch.setattr(monitor.pipeline.queue, "enqueue", full)
    with exclusive_runtime_lock(root / "writer.lock"):
        assert await monitor.tick()
    assert monitor.pipeline.queue.cursor(monitor.collector.identity) is None
    assert monitor.store.state()["collector"] == "BACKPRESSURE"
    monkeypatch.setattr(monitor.pipeline.queue, "enqueue", original)
    with exclusive_runtime_lock(root / "writer.lock"):
        assert await monitor.tick()
    assert monitor.pipeline.queue.counts() == {"DONE": 3}


@pytest.mark.asyncio
async def test_stop_flag_prevents_new_collection(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    monitor.store.request_stop()
    with exclusive_runtime_lock(root / "writer.lock"):
        assert not await monitor.tick()
    assert monitor.pipeline.queue.counts() == {}


def test_audit_tamper_and_nonempty_directory_refused(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="NOT_ADOPTED"):
        initialize(root, monitor.config)
    with monitor.store.database.transaction() as c:
        c.execute("UPDATE monitor_audit SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError, match="AUDIT_INTEGRITY"):
        RuntimeStore(root)


@pytest.mark.asyncio
async def test_llm_success_actual_core_with_fixture_client_and_unknown_cost(tmp_path, monkeypatch):
    root, monitor = setup(tmp_path, monkeypatch, assessment_mode="REAL_LLM")

    class FixtureLLM:
        async def generate_structured(self, *, request, response_model):
            import json

            if response_model.__name__ == "LLMInvestigationPlanDraft":
                value = {
                    "goal": "inspect candidate",
                    "steps": [
                        {
                            "tool_name": "read_authentication_context",
                            "tool_input": {"incident_id": str(monitor.config.incident_id)},
                            "purpose": "read fixture",
                        }
                    ],
                }
            else:
                context = json.loads(request.user_prompt)
                value = {
                    "observations": [],
                    "hypotheses": [],
                    "assessment": {
                        "severity": "info",
                        "confidence": 0.0,
                        "summary": "Fixture advisory",
                        "supporting_evidence_ids": [
                            e["evidence_id"] for e in context["EVIDENCE (UNTRUSTED DATA)"]
                        ],
                    },
                }
            return response_model.model_validate(value)

    monitor.client = FixtureLLM()
    # Complete this finite batch deterministically; lifecycle deadlines are tested
    # separately and CPU contention must not truncate the second fixture job.
    await monitor.tick()
    await monitor.investigate_one()
    assert monitor.store.jobs() == {"DONE": 2}
    with monitor.store.database.transaction(write=False) as c:
        import json

        for row in c.execute("SELECT result FROM monitor_findings"):
            result = json.loads(row[0])
            assert result["llm_calls"] == 2
            assert result["cost_estimate"] is None
            assert result["token_usage"] == [None, None]
            assert result["investigation"]["plan"]["steps"][0]["status"] == "completed"
            assert result["write_probe"] == "DENIED_HANDLER_NOT_REGISTERED"
