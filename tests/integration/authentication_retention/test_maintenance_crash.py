"""Observer publication and cursor recovery crashes; no cleanup DELETE transactions exist."""

import asyncio
import json
import multiprocessing
import os
from contextlib import ExitStack
from threading import Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, open_pipeline, security_check
from tests.integration.authentication_retention.test_retention_rotation import configured, journal
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational import native_authentication as native
from soc_agent.security_ai.operational.journal_health import collect_with_health
from soc_agent.security_ai.operational.retention import (
    MaintenanceLog,
    deny_cleanup,
    retention_plan,
    storage_metrics,
)

POINTS = tuple(f"MP-{n:02d}" for n in range(1, 8))


def child(root, point, pipe, nonce):
    p = open_pipeline(root, native.LinuxAuthenticationCollector.identity)
    audit = MaintenanceLog(root / "maintenance.sqlite", p)

    def stop():
        pipe.send((os.getpid(), nonce, point))
        Event().wait(60)
        raise AssertionError("OWNED_CHILD_NOT_TERMINATED")

    with exclusive_runtime_lock(root / "writer.lock"), ExitStack() as stack:
        if point in ("MP-01", "MP-02", "MP-03"):
            plan = retention_plan(p, audit=audit)
            if point == "MP-01":
                stop()
            commit = audit.database._commit

            def deny_commit(c):
                if point == "MP-02":
                    stop()
                commit(c)
                if point == "MP-03":
                    stop()

            stack.enter_context(patch.object(audit.database, "_commit", deny_commit))
            deny_cleanup(plan, audit=audit)
        elif point in ("MP-04", "MP-05", "MP-06"):
            collector = native.LinuxAuthenticationCollector.__new__(
                native.LinuxAuthenticationCollector
            )
            collector.include_pam_failures = False
            collector.collector_id = native.COLLECTOR
            from types import SimpleNamespace

            collector.native = SimpleNamespace(command="fixture-journal")
            if point == "MP-04":
                append = audit.append

                def started(*args):
                    result = append(*args)
                    if args[0] == "COLLECTION_START":
                        stop()
                    return result

                stack.enter_context(patch.object(audit, "append", started))
            else:
                commit = audit.database._commit

                def gap_commit(c):
                    last = c.execute(
                        "SELECT payload FROM auth_maintenance_events ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()
                    gap = last and json.loads(last[0])["status"] == "GAP_DETECTED"
                    if gap and point == "MP-05":
                        stop()
                    commit(c)
                    if gap and point == "MP-06":
                        stop()

                stack.enter_context(patch.object(audit.database, "_commit", gap_commit))
            stack.enter_context(patch.object(native, "bounded_command", journal([row(2, 30)])))
            collect_with_health(p, collector, audit=audit)
        else:
            p.queue.enqueue(
                native.project_journal(row(2, 30)), cursor_source=p.binding["collector"]
            )
            p.queue.claim()
            p.queue.recover()
            stop()
        raise AssertionError("MAINTENANCE_POINT_NOT_REACHED")


@pytest.mark.parametrize("point", POINTS)
def test_owned_maintenance_crash_preserves_evidence(tmp_path, point):
    p, audit, _ = configured(tmp_path)
    root = tmp_path / "private"
    p.queue.enqueue(native.project_journal(row()), cursor_source=p.binding["collector"])
    p.step()
    before = storage_metrics(p)
    cursor = p.queue.cursor(p.binding["collector"])
    ctx = multiprocessing.get_context("spawn")
    parent, receiver = ctx.Pipe(duplex=False)
    nonce = str(uuid4())
    proc = ctx.Process(target=child, args=(root, point, receiver, nonce))
    proc.start()
    receiver.close()
    try:
        kill_owned_checkpoint(proc, parent, nonce, point, root / "writer.lock")
        with exclusive_runtime_lock(root / "writer.lock"):
            restored = open_pipeline(root, native.LinuxAuthenticationCollector.identity)
            restored.queue.recover()
            for _ in range(4):
                if restored.step() == "IDLE":
                    break
            restored_log = MaintenanceLog(audit.database.path, restored)
            entries = restored_log.entries()
            if point in ("MP-01", "MP-02"):
                assert len(entries) == 1 and entries[-1]["status"] == "DRY_RUN"
            elif point == "MP-03":
                assert len(entries) == 2 and entries[-1]["status"] == "DENIED"
            elif point in ("MP-04", "MP-05"):
                assert len(entries) == 1 and entries[-1]["status"] == "STARTED"
                assert restored_log.health_counts()["collection_outcome_unknown"] == 1
            elif point == "MP-06":
                assert entries[-1]["status"] == "GAP_DETECTED"
            if point != "MP-07":
                assert restored.queue.cursor(restored.binding["collector"]) == cursor
                assert storage_metrics(restored) == before
            else:
                assert storage_metrics(restored)["source_record_count"] == 2
            assert asyncio.run(security_check(restored))["write_spy_calls"] == 0
            for db in (restored.queue.database, restored.store.database, restored_log.database):
                with db.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        if proc.is_alive():
            proc.kill()
            proc.join(10)
        parent.close()
        proc.close()
