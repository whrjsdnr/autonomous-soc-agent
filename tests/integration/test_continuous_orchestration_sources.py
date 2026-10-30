"""Stored/fixture inputs, actual local model artifacts, SCRIPTED investigation."""

from datetime import UTC, datetime

import pytest

from soc_agent.continuous.authentication import AuthenticationWindows, normalized
from soc_agent.continuous.investigation import application, from_analysis
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.security_ai.offline_workflow import OfflineWorkflow
from soc_agent.security_ai.workflow_models import CollectorFailureJob
from tests.integration.test_continuous_orchestration import Recorded, drained
from tests.integration.test_raw_dns_workflow import job, message
from tests.research_adapter_support import research_paths
from tests.unit.continuous.test_runtime import make, window
from tests.unit.continuous.test_stream_integration import auth, packages


@pytest.mark.asyncio
async def test_actual_models_and_three_domain_provenance_enter_core_runtime(tmp_path):
    _, store = make(tmp_path)
    tasks, client = InvestigationTasks(store), Recorded()
    windows = AuthenticationWindows(packages(), origin="FIXTURE")
    for i in range(42):
        windows.observe(normalized(auth(i), "a" * 64)[1], source_digest="a" * 64)
    authentication = windows.advance(
        datetime(2026, 1, 1, 0, 5, tzinfo=UTC), source_digest="a" * 64
    )[0]
    jobs = [window(), job(message(), message(True, at=120)), authentication]
    retained, predictions = [], []
    for i, item in enumerate(jobs):
        directory = tmp_path / f"analysis-{i}"
        outcome = await OfflineWorkflow(
            directory, paths=research_paths(), defer_investigation=True
        ).run(item)
        assert outcome.external_provider_calls == 0
        assert outcome.investigation is None
        source = from_analysis(directory, scope="a" * 64, namespace=store.config.namespace)
        assert from_analysis(directory, scope="a" * 64, namespace=store.config.namespace) == source
        assert source.incident_id == outcome.incident_id
        if i == 1:
            assert not source.advisory["model_results"] and outcome.eligibility == "INCOMPLETE"
        else:
            assert source.advisory["model_results"]
        retained.append(tasks.submit(source))
        predictions.append(len(outcome.inference))
    assert predictions == [2, 0, 1]
    await drained(tasks, client)
    assert {s.role for s in tasks.sources()} == {"NETWORK", "DNS", "AUTHENTICATION"}
    assert len({t.group for t in retained}) == 3  # Different clocks/targets are not merged.
    for task in retained:
        state = application(tasks, task, client).store.load(task.incident_id).state
        assert state.evidence and not state.observations
    assert len(tasks.snapshot()["tasks"]) == 3
    assert any("model_results" in request.user_prompt for request, _ in client.calls)


@pytest.mark.asyncio
async def test_unknown_collector_error_retains_original_failure_and_gets_plan(tmp_path):
    _, store = make(tmp_path)
    directory = tmp_path / "failure"
    outcome = await OfflineWorkflow(directory, defer_investigation=True).run(
        CollectorFailureJob(kind="collector_error", code="UNCLASSIFIED_TEST_ERROR")
    )
    tasks, client = InvestigationTasks(store), Recorded()
    task = tasks.submit(from_analysis(directory, scope="a" * 64, namespace=store.config.namespace))
    assert task.incident_id == outcome.incident_id
    await drained(tasks, client)
    assert any(name == "LLMInvestigationPlanDraft" for _, name in client.calls)
    assert any("UNCLASSIFIED_TEST_ERROR" in request.user_prompt for request, _ in client.calls)
    assert tasks.snapshot()["tasks"][0]["state"] == "WAITING_HUMAN"
    assert (
        application(tasks, task, client).checkpoint(task.incident_id).artifacts.execution_intent_id
        is None
    )
