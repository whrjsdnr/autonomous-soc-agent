"""Test-only owned-process crash injection; never installed in production entrypoints."""

import asyncio
import multiprocessing
import os
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4

from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.realtime.models import CommonEvent
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational import authentication_pipeline as pipeline_module
from soc_agent.security_ai.operational.authentication_investigation import (
    AuthenticationReadQuery,
    AuthenticationReadView,
    authentication_read_registry,
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.tools import Tool, ToolMetadata

POINTS = tuple(f"CP-{i:02d}" for i in range(1, 11))
INCIDENT = UUID(int=701)
OPTIONS = {"allowed_lateness_seconds": 60, "max_future_skew_seconds": 5}


def open_pipeline(root: Path, identity: str, *, create: bool = False):
    if create:
        create_private_directory(root, exist_ok=False)
        create_private_file(root / "writer.lock")
    queue = (
        EventQueue.create(root / "queue.sqlite") if create else EventQueue(root / "queue.sqlite")
    )
    store = (
        OperationalSourceStore.create(root / "sources.sqlite", **OPTIONS)
        if create
        else OperationalSourceStore(root / "sources.sqlite", **OPTIONS)
    )
    return AuthenticationPipeline(queue, store, INCIDENT, collector_identity=identity)


async def security_check(pipeline):
    result = await investigate_authentication(pipeline)
    assert result.plan.steps[0].status.value == "completed"
    registry = authentication_read_registry(pipeline)
    calls = []

    async def spy(value):
        calls.append(value)
        raise AssertionError("WRITE_HANDLER_CALLED")

    tool = Tool(
        ToolMetadata(
            name="disable_account",
            description="inert spy",
            permission="system_write",
            risk_level="high",
        ),
        AuthenticationReadQuery,
        AuthenticationReadView,
        spy,
        registry.execution_guard,
    )
    try:
        await tool.execute({"incident_id": str(INCIDENT)})
    except ExecutionDeniedError:
        pass
    else:
        raise AssertionError("WRITE_ALLOWED")
    assert not calls
    return {"agent_read_queries": 1, "write_attempts_blocked": 1, "write_spy_calls": 0}


def _child(root, identity, payload, point, channel, nonce):
    """Hooks only exist in this spawned test child; parent validates ownership before kill."""
    event = CommonEvent.model_validate_json(payload)
    pipeline = open_pipeline(Path(root), identity)

    def stop():
        channel.send((os.getpid(), nonce, point))
        # No busy loop and no system-wide signals. Parent must kill this exact child.
        multiprocessing.Event().wait(60)
        raise AssertionError("PARENT_DID_NOT_TERMINATE_CHILD")

    with exclusive_runtime_lock(Path(root) / "writer.lock"), ExitStack() as stack:
        if point == "CP-01":
            stop()  # projected collector batch exists in memory, no queue transaction yet
        if point in ("CP-02", "CP-03"):
            commit = pipeline.queue.database._commit

            def queue_commit(connection):
                if point == "CP-02":
                    stop()
                commit(connection)
                if point == "CP-03":
                    stop()  # both retained event and cursor have committed

            stack.enter_context(patch.object(pipeline.queue.database, "_commit", queue_commit))
        pipeline.queue.enqueue(event, cursor_source=identity)
        if point == "CP-04":
            claim = pipeline.queue.claim

            def claim_stop():
                value = claim()
                stop()
                return value

            stack.enter_context(patch.object(pipeline.queue, "claim", claim_stop))
        if point == "CP-05":
            commit = pipeline.store.database._commit

            def source_commit(connection):
                commit(connection)
                stop()

            stack.enter_context(patch.object(pipeline.store.database, "_commit", source_commit))
        if point == "CP-06":
            snapshot = pipeline.store._snapshot

            def snapshot_stop(connection, source):
                snapshot(connection, source)
                stop()  # SQL completed inside source/window transaction, not committed

            stack.enter_context(patch.object(pipeline.store, "_snapshot", snapshot_stop))
        if point == "CP-07":
            ingest = pipeline_module.ingest_authentication

            def ingest_stop(*args, **kwargs):
                receipt = ingest(*args, **kwargs)
                stop()  # complete provenance exists in memory, queue receipt not published
                return receipt

            stack.enter_context(patch.object(pipeline_module, "ingest_authentication", ingest_stop))
        if point in ("CP-08", "CP-09"):
            finish = pipeline.queue.finish

            def finish_stop(*args, **kwargs):
                if point == "CP-08":
                    stop()
                finish(*args, **kwargs)
                if point == "CP-09":
                    stop()

            stack.enter_context(patch.object(pipeline.queue, "finish", finish_stop))
        pipeline.step()
        if point == "CP-10":
            windows = pipeline.store.windows

            def windows_stop(*args, **kwargs):
                value = windows(*args, **kwargs)
                stop()  # real governed read handler is revalidating persisted state
                return value

            stack.enter_context(patch.object(pipeline.store, "windows", windows_stop))
            asyncio.run(investigate_authentication(pipeline))
        raise AssertionError("CRASH_POINT_NOT_REACHED")


def kill_owned_checkpoint(process, channel, nonce, point, lock_path):
    """Kill only this parent's live Process after PID/nonce/lock ownership handshake."""
    if not channel.poll(20):
        raise AssertionError("CRASH_HANDSHAKE_TIMEOUT")
    pid, received_nonce, reached = channel.recv()
    assert pid == process.pid and received_nonce == nonce and reached == point
    assert process.is_alive() and process in multiprocessing.active_children()
    try:
        with exclusive_runtime_lock(lock_path):
            raise AssertionError("CONCURRENT_WRITER_LOCK_GRANTED")
    except OSError:
        pass
    process.kill()
    process.join(10)
    assert not process.is_alive() and process.exitcode != 0


def crash_case(root: Path, event: CommonEvent, point: str, *, identity=None):
    if point not in POINTS:
        raise ValueError("UNKNOWN_CRASH_POINT")
    identity = identity or LinuxAuthenticationCollector.identity
    open_pipeline(root, identity, create=True)
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    nonce = str(uuid4())
    process = ctx.Process(
        target=_child, args=(str(root), identity, event.model_dump_json(), point, child, nonce)
    )
    started = time.monotonic()
    process.start()
    child.close()
    try:
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        p = open_pipeline(root, identity)
        with exclusive_runtime_lock(root / "writer.lock"):
            cursor_before = p.queue.cursor(identity)
            assert (cursor_before is None) == (point in ("CP-01", "CP-02"))
            with p.store.database.transaction(write=False) as c:
                sources_before = c.execute("SELECT count(*) FROM operational_sources").fetchone()[0]
            assert sources_before == (
                0 if point in ("CP-01", "CP-02", "CP-03", "CP-04", "CP-06") else 1
            )
            p.queue.recover()
            added = p.queue.enqueue(event, cursor_source=identity)
            assert added == (point in ("CP-01", "CP-02"))
            for _ in range(5):
                if p.step() == "IDLE":
                    break
            else:
                raise AssertionError("RECOVERY_DRAIN_LIMIT")
            view = read_authentication_view(p)
            assert view.authentication_events_verified == 1
            assert sum(w.total for w in view.authentication_window) == 1
            assert view.inference_status == "NOT_INFERABLE" and view.action_policy == "WRITE_DENIED"
            assert p.queue.counts() == {"DONE": 1}
            assert p.queue.cursor(identity).source_digest == event.source_digest
            security = asyncio.run(security_check(p))
            for db in (p.queue.database, p.store.database):
                with db.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                    assert not c.execute("PRAGMA foreign_key_check").fetchall()
        return {
            "point": point,
            "status": "PASS",
            "elapsed_seconds": time.monotonic() - started,
            "exitcode": process.exitcode,
            "source_rows_before_recovery": sources_before,
            "event_loss": 0,
            "duplicate_window_effect": 0,
            **security,
        }
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        parent.close()
        process.close()
