import asyncio

from tests.unit.realtime.test_pipeline import event

from soc_agent.realtime.queue import EventQueue
from soc_agent.realtime.worker import composition, drain
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore


def test_common_event_queue_actual_runtime_restart(tmp_path):
    root = tmp_path / "private"
    q = EventQueue.create(root / "queue.sqlite")
    store = RuntimeGovernanceStore.create_isolated(root / "runtime")
    application = composition(store)
    first = event()
    q.enqueue(first, cursor_source="collector")
    asyncio.run(drain(q, application))
    assert q.counts() == {"DONE": 1}
    with q.database.transaction(write=False) as c:
        outcome = c.execute("SELECT outcome FROM realtime_events").fetchone()[0]
        assert "NOT_INFERABLE" in outcome
    q = EventQueue(q.database.path)
    store = RuntimeGovernanceStore(store.database.path)
    application = composition(store)
    assert not q.enqueue(first, cursor_source="collector")
    asyncio.run(drain(q, application))
    assert q.counts() == {"DONE": 1}


def test_hard_exit_after_claim_recovery(tmp_path):
    import os
    import subprocess
    import sys

    q = EventQueue.create(tmp_path / "private" / "queue.sqlite")
    q.enqueue(event(), cursor_source="collector")
    script = (
        "import os,sys; from pathlib import Path; "
        "from soc_agent.realtime.queue import EventQueue; "
        "q=EventQueue(Path(sys.argv[1])); assert q.claim(); os._exit(23)"
    )
    child = subprocess.run(
        [sys.executable, "-c", script, str(q.database.path)],
        capture_output=True,
        timeout=30,
        env=os.environ.copy(),
    )
    assert child.returncode == 23
    q = EventQueue(q.database.path)
    assert q.cursor("collector").event_id == event().event_id
    q.recover()
    claim = q.claim()
    assert claim.attempts == 2
    q.finish(claim, {"inference": "NOT_INFERABLE"})
    assert q.counts() == {"DONE": 1}


def test_runtime_committed_ack_lost_replay_is_idempotent(tmp_path):
    from soc_agent.realtime.worker import incident_id, process

    q = EventQueue.create(tmp_path / "private" / "queue.sqlite")
    store = RuntimeGovernanceStore.create_isolated(tmp_path / "private" / "runtime")
    app = composition(store)
    first = event()
    q.enqueue(first)
    lost = q.claim()
    result = asyncio.run(process(app, first))
    before = store.load(incident_id(first))
    q.recover()
    again = q.claim()
    assert again.token != lost.token
    second = asyncio.run(process(app, again.event))
    after = store.load(incident_id(first))
    assert result == second
    assert before.anchor == after.anchor
    assert len([e for e in after.state.evidence if e.source == "common-event:v1"]) == 1
    q.finish(again, second)


def test_worker_exception_is_bounded_and_poison_retained(tmp_path, monkeypatch):
    import pytest

    import soc_agent.realtime.worker as worker

    q = EventQueue.create(tmp_path / "private" / "queue.sqlite", retry_limit=2)
    q.enqueue(event())

    async def failed(*_):
        raise RuntimeError("Backend unavailable")

    monkeypatch.setattr(worker, "process", failed)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="unavailable"):
            asyncio.run(worker.drain(q, None))
    assert q.counts() == {"POISON": 1}
    assert q.claim() is None
