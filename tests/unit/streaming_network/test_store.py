"""Flow-only persistence, durable outcomes, tamper rejection and no-retry recovery."""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from tests.streaming_network_support import packet

from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy, prepare
from soc_agent.security_ai.operational.network_capture.streaming_flow import StreamingFlows
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_store import StreamStore


def store_and_flow(tmp_path, **policy):
    directory = tmp_path / "session"
    session = prepare(directory, StreamPolicy(**policy))
    store = StreamStore(directory, session, fixture=True, create=True)
    owner = SimpleNamespace(session=session)
    flows = StreamingFlows()
    for t in (0, 1):
        flows.add(packet(owner, t), uuid4())
    completed = flows.add(packet(owner, 31), uuid4())[0]
    return store, completed


def test_compact_source_commit_binding_and_post_outcome_purge(tmp_path):
    store, completed = store_and_flow(tmp_path)
    event = store.commit(completed, (1, 4))
    request, env = store.load(event, "quality")
    assert request.origin == "FIXTURE"
    assert env.values == completed.values
    assert "packets" not in dict(event.normalized_fields)
    assert len(list((store.directory / "inputs").glob("*"))) == 1
    with pytest.raises(ValueError, match="BEFORE_DURABLE"):
        store.purge(event)
    claim = store.queue.claim()
    store.finish(claim, "RESEARCH_COMPLETE")
    assert not list((store.directory / "inputs").glob("*"))
    assert store.queue.counts() == {"DONE": 1}
    assert not store.queue.enqueue(event)
    assert store.runtime.verify_audit()
    store.recover_no_retry()
    assert store.queue.counts() == {"DONE": 1}


@pytest.mark.parametrize("tampering", ["packet", "feature", "origin", "session"])
def test_input_tampering_is_rejected_and_preserved_for_review(tmp_path, tampering):
    store, completed = store_and_flow(tmp_path)
    event = store.commit(completed, (1, 4))
    path = next((store.directory / "inputs").glob("*"))
    data = json.loads(path.read_text())
    if tampering == "packet":
        data["packets"][0]["ip_length"] += 1
    if tampering == "feature":
        data["values"][0] += 1
    if tampering == "origin":
        data["origin"] = "NATIVE_AF_PACKET"
    if tampering == "session":
        data["capture_session"] = str(uuid4())
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        store.load(event, "quality")
    with pytest.raises(ValueError):
        store.recover_no_retry()
    assert path.exists()


def test_no_purge_when_queue_done_lacks_durable_outcome(tmp_path):
    store, completed = store_and_flow(tmp_path)
    event = store.commit(completed, (1, 4))
    claim = store.queue.claim()
    store.queue.finish(claim, {"workflow": "UNTRUSTED_NO_OUTCOME"})
    with pytest.raises(ValueError, match="AUDIT_OUTCOME_MISSING"):
        store.purge(event)
    assert list((store.directory / "inputs").glob("*"))


def test_recover_claim_no_model_retry_and_audit_corruption(tmp_path):
    store, completed = store_and_flow(tmp_path)
    store.commit(completed, (1, 4))
    store.queue.claim()
    store.recover_no_retry()
    assert store.queue.counts() == {"DONE": 1}
    assert not list((store.directory / "inputs").glob("*"))
    with store.runtime.database.transaction() as c:
        c.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("0" * 64,))
    with pytest.raises(ValueError, match="AUDIT_INTEGRITY"):
        store.recover_no_retry()


def test_backpressure_and_duplicate_flow_are_explicit(tmp_path):
    store, completed = store_and_flow(tmp_path, inference_capacity=1)
    store.commit(completed, (1, 4))
    with pytest.raises(ValueError, match="BACKPRESSURE"):
        store.commit(completed, (1, 4))
    assert len(list((store.directory / "inputs").glob("*"))) == 1
    assert digest(completed.values)
