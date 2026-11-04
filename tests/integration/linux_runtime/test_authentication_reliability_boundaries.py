"""Owned fixture I/O/STOP ordering; no Host collection, inference or API."""

import asyncio
import threading

import pytest
from tests.integration.linux_runtime.test_monitor import setup

from soc_agent.linux_runtime import service
from soc_agent.security_ai.operational import authentication_investigation


def test_journal_fixture_preserves_failed_and_explicit_mixed_authentication_inputs():
    from tests.integration.linux_runtime.test_managed_authentication_lifecycle import (
        journal_fixture_rows,
    )

    from soc_agent.security_ai.operational.native_authentication import project_journal

    def results(rows):
        return [
            dict(project_journal(row).normalized_fields)["authentication_result"] for row in rows
        ]

    assert results(journal_fixture_rows()) == ["failure", "failure", "failure"]
    messages = [
        "Accepted password for fixture-user from 192.0.2.5 port 34567 ssh2",
        "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2",
    ]
    assert results(journal_fixture_rows((1, 2), messages)) == ["success", "failure"]


def test_authentication_cli_import_does_not_load_models():
    import subprocess
    import sys

    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import soc_agent.linux_runtime.__main__; "
            "assert 'numpy' not in sys.modules; assert 'sklearn' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert child.returncode == 0, child.stderr


@pytest.mark.asyncio
async def test_stop_after_completion_commit_never_finishes_the_job_twice(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)
    committed, release = threading.Event(), threading.Event()
    statuses = []
    original = monitor.store.finish

    def finish(finding, status, *args, **kwargs):
        original(finding, status, *args, **kwargs)
        statuses.append(status)
        committed.set()
        assert release.wait(3)

    monkeypatch.setattr(monitor.store, "finish", finish)
    tick = asyncio.create_task(monitor.tick())
    try:
        assert await asyncio.to_thread(committed.wait, 2)
        tick.cancel()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await tick
    assert statuses == ["DONE_READ_ONLY"]
    assert monitor.store.jobs() == {"DONE_READ_ONLY": 1, "PENDING": 1}


@pytest.mark.asyncio
async def test_stop_after_claim_commit_returns_unstarted_work_to_pending(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)

    # Prepare real ingestion before timing the claim/cancellation interleaving.
    # Disk work unrelated to claiming is covered by the lifecycle tests.
    async def defer_investigation():
        return None

    with monkeypatch.context() as preparation:
        preparation.setattr(monitor, "investigate_one", defer_investigation)
        await monitor.tick()
    assert monitor.store.jobs() == {"PENDING": 2}
    committed, release = threading.Event(), threading.Event()
    original = monitor.store.claim

    def claim():
        result = original()
        committed.set()
        assert release.wait(3)
        return result

    monkeypatch.setattr(monitor.store, "claim", claim)
    tick = asyncio.create_task(monitor.investigate_one())
    try:
        assert await asyncio.to_thread(committed.wait, 2)
        tick.cancel()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await tick
    assert monitor.store.jobs() == {"PENDING": 2}


@pytest.mark.asyncio
async def test_collection_storage_never_executes_on_control_loop(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)
    loop_thread = threading.get_ident()
    original = service.collect_with_health

    def collect(*args, **kwargs):
        assert threading.get_ident() != loop_thread, "AUTH_STORAGE_BLOCKED_CONTROL_LOOP"
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "collect_with_health", collect)
    await monitor.tick()
    assert monitor.pipeline.queue.counts() == {"DONE": 3}


@pytest.mark.asyncio
async def test_read_only_evidence_tool_never_executes_storage_on_control_loop(
    tmp_path, monkeypatch
):
    _, monitor = setup(tmp_path, monkeypatch)
    loop_thread = threading.get_ident()
    original = authentication_investigation.read_authentication_view

    def read(*args, **kwargs):
        assert threading.get_ident() != loop_thread, "AUTH_READ_TOOL_BLOCKED_CONTROL_LOOP"
        return original(*args, **kwargs)

    monkeypatch.setattr(authentication_investigation, "read_authentication_view", read)
    await monitor.tick()
    assert monitor.store.jobs() == {"DONE_READ_ONLY": 1, "PENDING": 1}


@pytest.mark.asyncio
async def test_collector_ready_is_published_after_first_ingestion_batch(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    original = monitor.pipeline.step

    def step():
        entered.set()
        assert release.wait(3)
        return original()

    monkeypatch.setattr(monitor.pipeline, "step", step)
    tick = asyncio.create_task(monitor.tick())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        assert monitor.store.state()["collector"] == "NOT_STARTED"
        assert monitor.pipeline.queue.counts() == {"PENDING": 3}
    finally:
        release.set()
        await tick
    assert monitor.store.state()["collector"] == "INITIAL_READ"
    assert monitor.pipeline.queue.counts() == {"DONE": 3}


@pytest.mark.asyncio
async def test_cancelled_storage_is_joined_before_owner_can_report_stop(tmp_path, monkeypatch):
    _, monitor = setup(tmp_path, monkeypatch)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def write():
        entered.set()
        assert release.wait(3)
        finished.set()

    pending = asyncio.create_task(monitor.storage(write))
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        pending.cancel()
        observed = asyncio.Event()
        asyncio.get_running_loop().call_soon(observed.set)
        await observed.wait()
        assert not pending.done() and not finished.is_set()
        pending.cancel()  # A shutdown deadline can cancel the same owner again.
        observed.clear()
        asyncio.get_running_loop().call_soon(observed.set)
        await observed.wait()
        assert not pending.done() and not finished.is_set()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await pending
    assert finished.is_set()


@pytest.mark.asyncio
async def test_cancelled_state_observer_is_joined_before_cleanup(tmp_path, monkeypatch):
    from tests.integration.linux_runtime.test_managed_authentication_lifecycle import (
        approve_fixture,
        mock_journal_child,
        prepare,
    )

    from soc_agent.continuous.authentication_lifecycle import AuthenticationLifecycle

    store = prepare(tmp_path)
    approve_fixture(store)
    mock_journal_child(monkeypatch)
    child = AuthenticationLifecycle(store)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    watcher = closing = None
    try:
        await child.start()
        original = child._read

        def blocked():
            entered.set()
            assert release.wait(3)
            value = original()
            finished.set()
            return value

        monkeypatch.setattr(child, "_read", blocked)
        watcher = asyncio.create_task(child.watch(asyncio.Event()))
        assert await asyncio.to_thread(entered.wait, 1)
        watcher.cancel()
        with pytest.raises(asyncio.CancelledError):
            await watcher
        assert child._reader is not None and not child._reader.done()
        closing = asyncio.create_task(child.close())
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(closing), 0.2)
        assert not child.cleanup_written and not finished.is_set()
    finally:
        release.set()
        if watcher and not watcher.done():
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
        if closing:
            await closing
        else:
            await child.close()
    assert finished.is_set() and child.evidence["state_reader_joined"]
    assert child.evidence["cleanup"] == "VERIFIED"


@pytest.mark.parametrize("table", ["monitor_config", "monitor_audit", "monitor_state"])
def test_atomic_observation_keeps_every_integrity_check(tmp_path, monkeypatch, table):
    import json

    from soc_agent.linux_runtime.store import RuntimeStore

    _, monitor = setup(tmp_path, monkeypatch)
    with monitor.store.database.transaction() as c:
        row = c.execute(f"SELECT payload FROM {table} LIMIT 1").fetchone()
        body = json.loads(row["payload"])
        body["changed_without_digest"] = True
        c.execute(f"UPDATE {table} SET payload=?", (json.dumps(body),))
    with pytest.raises(ValueError):
        RuntimeStore.observation(monitor.directory)


@pytest.mark.asyncio
async def test_operator_stop_cancels_read_only_work_before_outer_five_second_budget(
    tmp_path, monkeypatch
):
    _, monitor = setup(tmp_path, monkeypatch)
    entered, release = asyncio.Event(), asyncio.Event()

    async def investigation():
        entered.set()
        await release.wait()

    monkeypatch.setattr(monitor, "investigate_one", investigation)
    running = asyncio.create_task(monitor.run())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        monitor.request_stop()
        # The parent's unchanged 5s budget cannot contain another full 5s
        # investigation grace followed by durable STOP/ACK records.
        await asyncio.wait_for(asyncio.shield(running), 1)
    finally:
        release.set()
        await asyncio.wait_for(running, 6)
    assert monitor.store.state()["state"] == "STOPPED"
    assert monitor.pipeline.queue.counts() == {"DONE": 3}
