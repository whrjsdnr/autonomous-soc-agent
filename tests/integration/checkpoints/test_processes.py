"""Independent interpreter resume/advance contention, not a thread-only simulation."""

import asyncio
import multiprocessing
from pathlib import Path
from uuid import UUID

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.execution import GovernedExecutor
from soc_agent.execution.durable import DurableExecutor, ExecutionStore
from soc_agent.investigation import InvestigationOrchestrator
from soc_agent.investigation.runtime import SOCRuntime
from soc_agent.investigation.runtime.persistence import CheckpointStore
from soc_agent.investigation.runtime.persistence.models import StaleCheckpoint, WorkflowInFlight
from soc_agent.llm import MockLLMClient
from soc_agent.planning import InvestigationPlanner
from soc_agent.policy import PolicyEngine
from soc_agent.response.advisory import PersistentPlanningSource, ResponsePlanner
from soc_agent.response.promotion import ExecutionBridge, PromotionService
from soc_agent.review.persistence import SQLiteGovernanceStore
from soc_agent.tools import ToolRegistry


def worker(path, incident_id, barrier, queue):
    store = SQLiteGovernanceStore(Path(path))
    registry, policy, approvals = ToolRegistry(), PolicyEngine(), ApprovalManager()
    llm = MockLLMClient([])  # Any repeated analysis would fail, not silently succeed.
    runtime = SOCRuntime(
        store=store,
        investigator=InvestigationOrchestrator(
            executor=GovernedExecutor(registry=registry, policy=policy, approvals=approvals)
        ),
        planner=InvestigationPlanner(llm_client=llm, registry=registry),
        assessor=ThreatAssessor(llm_client=llm),
        responses=ResponsePlanner(registry=registry, source=PersistentPlanningSource(store)),
        bridge=ExecutionBridge(
            promotions=PromotionService(store=store, registry=registry, policy=policy),
            approvals=approvals,
        ),
        executor=DurableExecutor(store=ExecutionStore(store), registry=registry, policy=policy),
        checkpoints=CheckpointStore(store),
    )
    runtime.restore(UUID(incident_id))
    barrier.wait(timeout=30)
    try:
        result = asyncio.run(runtime.advance(UUID(incident_id)))
        queue.put(("advanced", result.current_step.value, result.next_step.value, llm.call_count))
    except (StaleCheckpoint, WorkflowInFlight):
        queue.put(("conflict",))


@pytest.mark.asyncio
@pytest.mark.parametrize("before", [0, 3])
async def test_independent_process_resume_cas(runtime_case, before):
    c = runtime_case(durable_workflow=True)
    for _ in range(before):
        await c.runtime.advance(c.incident_id)
    saved, old_trace = CheckpointStore(c.store).load(c.incident_id)
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=worker, args=(str(c.store.database.path), str(c.incident_id), barrier, queue)
        )
        for _ in range(2)
    ]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=45)
            assert process.exitcode == 0
        outcomes = [queue.get(timeout=5) for _ in processes]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        queue.close()
    assert sorted(r[0] for r in outcomes) == ["advanced", "conflict"]
    winner = next(r for r in outcomes if r[0] == "advanced")
    assert winner[1:] == (("observe", "route", 0) if before == 0 else ("decide", "govern", 0))
    after, trace = CheckpointStore(c.store).load(c.incident_id)
    assert after.revision == saved.revision + 1
    assert trace.entries[:-1] == old_trace.entries
