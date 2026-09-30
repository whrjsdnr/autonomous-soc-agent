from uuid import uuid4

import pytest
from pydantic import ValidationError

from soc_agent.investigation.runtime import OrchestrationTrace, OrchestrationTraceEntry
from soc_agent.investigation.runtime.trace import TraceContent
from soc_agent.review.identity import content_digest
from tests.unit.investigation_runtime.conftest import decision_ready, review_for


@pytest.mark.asyncio
async def test_trace_immutable_deterministic_and_preserved_after_resume(runtime_case):
    case = runtime_case()
    await decision_ready(case)
    await case.runtime.advance(case.incident_id)
    trace = case.runtime.trace(case.incident_id)
    for _ in range(3):
        await case.runtime.advance(case.incident_id)
        assert case.runtime.trace(case.incident_id) == trace
    with pytest.raises(ValidationError):
        trace.entries = ()
    with pytest.raises(ValidationError):
        trace.entries[0].content.result.reason = "changed"
    restored = OrchestrationTrace.model_validate_json(trace.model_dump_json())
    assert restored == trace
    assert all(e.entry_id == content_digest(e.content) for e in restored.entries)
    await case.runtime.advance(case.incident_id, review=review_for(case))
    resumed = case.runtime.trace(case.incident_id)
    assert resumed.entries[: len(trace.entries)] == trace.entries
    assert len(resumed.entries) == len(trace.entries) + 1
    assert case.llm.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation", ["sequence", "incident", "artifact", "snapshot", "order", "drop"]
)
async def test_trace_corruption_rejected(runtime_case, mutation):
    case = runtime_case()
    await decision_ready(case)
    payload = case.runtime.trace(case.incident_id).model_dump(mode="json")
    last = payload["entries"][-1]["content"]
    if mutation == "sequence":
        last["sequence"] += 2
    elif mutation == "incident":
        payload["incident_id"] = str(uuid4())
    elif mutation == "artifact":
        last["result"]["references"][0]["identity"] = "substituted"
    elif mutation == "snapshot":
        last["snapshot"]["fingerprint"] = "a" * 64
    elif mutation == "order":
        payload["entries"].reverse()
    else:
        payload["entries"].pop(1)
    with pytest.raises(ValueError):
        OrchestrationTrace.model_validate(payload)


@pytest.mark.asyncio
async def test_rehashed_artifact_substitution_not_accepted_as_runtime_trace(runtime_case):
    case = runtime_case()
    await decision_ready(case)
    trace = case.runtime.trace(case.incident_id)
    payload = trace.entries[-1].content.model_dump()
    payload["result"]["references"][0]["identity"] = "another-assessment"
    content = TraceContent.model_validate(payload)
    replacement = OrchestrationTraceEntry(entry_id=content_digest(content), content=content)
    changed = OrchestrationTrace(
        incident_id=case.incident_id, entries=(*trace.entries[:-1], replacement)
    )
    with pytest.raises(ValueError, match="artifact bindings"):
        case.runtime.validate_trace(changed)
    assert case.runtime.trace(case.incident_id) == trace


@pytest.mark.asyncio
async def test_cross_incident_and_duplicate_entries_rejected(runtime_case):
    a, b = runtime_case(), runtime_case()
    await decision_ready(a)
    await decision_ready(b)
    trace = a.runtime.trace(a.incident_id)
    foreign = b.runtime.trace(b.incident_id).entries[-1]
    with pytest.raises(ValueError):
        OrchestrationTrace(incident_id=a.incident_id, entries=(*trace.entries, foreign))
    # Deliberate duplicate with fresh sequence/hash still fails semantic deduplication.
    last = trace.entries[-1]
    content = TraceContent(
        sequence=len(trace.entries) + 1,
        snapshot=last.content.snapshot,
        result=last.content.result,
        previous_entry_id=last.entry_id,
    )
    duplicate = OrchestrationTraceEntry(entry_id=content_digest(content), content=content)
    with pytest.raises(ValueError, match="Duplicate"):
        OrchestrationTrace(incident_id=a.incident_id, entries=(*trace.entries, duplicate))


@pytest.mark.asyncio
async def test_cancelled_dispatch_retains_contiguous_trace(runtime_case, monkeypatch):
    import asyncio

    from .support import promote_response

    case = runtime_case()
    await promote_response(case)

    async def cancelled(*args, **kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(case.executor, "execute", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await case.runtime.advance(case.incident_id, execute=True)
    await case.runtime.advance(case.incident_id)
    trace = case.runtime.trace(case.incident_id)
    assert case.runtime.validate_trace(trace) == trace
    assert trace.entries[-1].content.result.waiting_for_human
    assert case.mocks["inspect_logs"].call_count == 0
