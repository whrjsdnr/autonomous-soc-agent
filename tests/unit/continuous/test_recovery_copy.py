"""Recovery copies only; no original queue reset, Native authority or external API."""

import json

import pytest
from tests.unit.continuous.test_runtime import make, window

from soc_agent.continuous.cli import code_identity
from soc_agent.continuous.recovery import clone_replay, inspect_queue, inventory
from soc_agent.continuous.service import ContinuousRuntime
from soc_agent.continuous.store import Store
from soc_agent.security_ai.workflow_models import CollectorFailureJob


def baseline(tmp_path, **config):
    directory, store = make(tmp_path, **config)
    (directory / "code-identity").write_text(code_identity())
    (directory / "code-identity").chmod(0o600)
    (directory / "service.lock").touch(mode=0o600)
    store.update(dict(state="STOPPED", cleanup="VERIFIED", collection_live=False))
    return directory, store


def test_pending_claimed_done_dead_letters_and_source_preservation(tmp_path):
    source, store = baseline(tmp_path)
    for code in ("DONE", "POISON", "CRASHED", "PENDING"):
        store.enqueue(CollectorFailureJob(kind="collector_error", code="FIXTURE_" + code))
    done = store.queue.claim()
    store.queue.finish(done, dict(workflow="FIXTURE_ACK_ONLY_NO_MODEL"))
    store.queue.fail(store.queue.claim(), "INVALID_INPUT")
    store.queue.claim()  # Uncertain in-flight work cannot be silently replayed.
    before = inventory(source)
    target = tmp_path / "copy"
    result = clone_replay(source, target)
    assert result["native_authority"] == "NOT_GRANTED" and result["source_unchanged"]
    copied = Store(target)
    assert copied.queue.counts() == dict(DONE=1, POISON=1, CLAIMED=1, PENDING=1)
    copied.queue.recover()  # Target's existing retry_limit=1; not an attempt reset.
    assert copied.queue.counts() == dict(DONE=1, POISON=2, PENDING=1)
    with pytest.raises(ValueError, match="Stale worker acknowledgement"):
        copied.queue.finish(done, {})
    assert inventory(source) == before
    assert inspect_queue(source)["in_flight"] == 1


@pytest.mark.parametrize("fault", ["checkpoint", "input", "native", "cleanup"])
def test_recovery_rejects_corruption_native_and_uncertain_cleanup(tmp_path, fault):
    source, store = baseline(tmp_path)
    store.enqueue(CollectorFailureJob(kind="collector_error", code="FIXTURE"))
    if fault == "checkpoint":
        with store.database.transaction() as c:
            c.execute("UPDATE continuous_checkpoint SET digest=?", ("0" * 64,))
    elif fault == "input":
        next((source / "inputs").glob("*.json")).write_text("{}")
    elif fault == "native":
        with store.database.transaction() as c:
            cfg = store.config.model_copy(update=dict(source="NATIVE_SERVICE"))
            from soc_agent.security_ai.research.models import digest

            c.execute(
                "UPDATE continuous_config SET payload=?,digest=?",
                (cfg.model_dump_json(), digest(cfg.model_dump(mode="json"))),
            )
    else:
        store.update(dict(state="STOPPED", cleanup="UNVERIFIED", collection_live=False))
    before = inventory(source)
    with pytest.raises(ValueError):
        clone_replay(source, tmp_path / "copy")
    assert inventory(source) == before


def test_recovery_refuses_active_writer_and_existing_target(tmp_path):
    from soc_agent.runtime_lock import exclusive_runtime_lock

    source, _ = baseline(tmp_path)
    with exclusive_runtime_lock(source / "service.lock"):
        with pytest.raises(BlockingIOError):
            clone_replay(source, tmp_path / "copy")
    with pytest.raises(ValueError, match="FRESH_SEPARATE_TARGET"):
        clone_replay(source, source / "copy")


@pytest.mark.asyncio
async def test_identical_window_handoff_at_quota_and_changed_input_rejected(tmp_path):
    source, store = baseline(tmp_path, max_windows=1)
    runtime = ContinuousRuntime(source)
    item = window()
    await runtime.handoff(item)
    await runtime.handoff(item)
    assert len(list((source / "inputs").glob("*.json"))) == 1
    assert store.queue.counts() == dict(PENDING=1)
    next((source / "inputs").glob("*.json")).write_text("{}")
    with pytest.raises(ValueError, match="INPUT_CHANGED"):
        await runtime.handoff(item)
    await runtime.analysis.close()


@pytest.mark.asyncio
async def test_rebuilt_event_time_witness_survives_first_replay_start(tmp_path):
    source, _ = baseline(tmp_path)
    runtime = ContinuousRuntime(source)
    runtime.metrics["recovered_events"] = 1
    runtime.last_event_ns = 90000000000
    observed = []

    class EmptySource:
        async def events(self):
            if False:
                yield {}

        async def close(self):
            pass

    async def complete(items, witness):
        observed.append(witness)

    runtime.source = EmptySource()
    runtime.complete = complete
    await runtime.collect()
    assert observed == [90000000000]
    await runtime.analysis.close()


def test_recovery_lineage_is_appended_not_an_execution_receipt(tmp_path):
    source, store = baseline(tmp_path)
    store.enqueue(CollectorFailureJob(kind="collector_error", code="FIXTURE"))
    target = tmp_path / "copy"
    clone_replay(source, target)
    lineage = json.loads((target / "recovery-source.json").read_text())
    assert not lineage["native_authority"] and not lineage["dead_letters_requeued"]
    assert lineage["previous_code"] == lineage["current_code"] == code_identity()
    assert inspect_queue(target)["audit"] == "VERIFIED"
