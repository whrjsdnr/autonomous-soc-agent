"""Owned process crash points for read-only manifest/capacity and observer publication."""

import asyncio
import multiprocessing
import os
from contextlib import ExitStack
from threading import Event
from unittest.mock import patch
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, open_pipeline, security_check
from tests.integration.archive_capacity.test_archive_capacity import configured

from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.archive import archive_manifest
from soc_agent.security_ai.operational.authentication_investigation import (
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.capacity import capacity_observation, record_capacity
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.retention import MaintenanceLog

POINTS = tuple(f"AP-{i:02d}" for i in range(1, 7))


def child(root, request, point, pipe, nonce):
    p = open_pipeline(root, LinuxAuthenticationCollector.identity)
    log = MaintenanceLog(root / "maintenance.sqlite", p)

    def stop():
        pipe.send((os.getpid(), nonce, point))
        Event().wait(60)
        raise AssertionError("OWNED_CHILD_NOT_KILLED")

    with exclusive_runtime_lock(root / "writer.lock"), ExitStack() as stack:
        if point == "AP-01":
            decode = p.store._decode

            def decode_stop(row):
                result = decode(row)
                stop()
                return result

            stack.enter_context(patch.object(p.store, "_decode", decode_stop))
            archive_manifest(p, request)
        elif point == "AP-02":
            archive_manifest(p, request)
            stop()
        elif point == "AP-03":
            connect = p.queue.database._connect

            def connect_stop():
                result = connect()
                stop()
                return result

            stack.enter_context(patch.object(p.queue.database, "_connect", connect_stop))
            capacity_observation(p)
        elif point in ("AP-04", "AP-05"):
            observation = capacity_observation(p)
            commit = log.database._commit

            def commit_stop(c):
                if point == "AP-04":
                    stop()
                commit(c)
                if point == "AP-05":
                    stop()

            stack.enter_context(patch.object(log.database, "_commit", commit_stop))
            record_capacity(log, observation)
        else:
            windows = p.store.windows

            def windows_stop(*args):
                result = windows(*args)
                stop()
                return result

            stack.enter_context(patch.object(p.store, "windows", windows_stop))
            asyncio.run(investigate_authentication(p))
        raise AssertionError("POINT_NOT_REACHED")


@pytest.mark.parametrize("point", POINTS)
def test_manifest_capacity_crash_source_unchanged(tmp_path, point):
    p, _, request = configured(tmp_path)
    root = tmp_path / "private"
    log = MaintenanceLog.create(root / "maintenance.sqlite", p)
    before = read_authentication_view(p)
    cursor = p.queue.cursor(p.binding["collector"])
    manifest = archive_manifest(p, request)
    ctx = multiprocessing.get_context("spawn")
    receiver, sender = ctx.Pipe(duplex=False)
    nonce = str(uuid4())
    proc = ctx.Process(target=child, args=(root, request, point, sender, nonce))
    proc.start()
    sender.close()
    try:
        kill_owned_checkpoint(proc, receiver, nonce, point, root / "writer.lock")
        with exclusive_runtime_lock(root / "writer.lock"):
            restored = open_pipeline(root, LinuxAuthenticationCollector.identity)
            assert read_authentication_view(restored) == before
            assert restored.queue.cursor(restored.binding["collector"]) == cursor
            assert archive_manifest(restored, request).manifest_digest == manifest.manifest_digest
            entries = MaintenanceLog(log.database.path, restored).entries()
            assert len(entries) == (1 if point == "AP-05" else 0)
            assert asyncio.run(security_check(restored))["write_spy_calls"] == 0
            for db in (restored.queue.database, restored.store.database, log.database):
                with db.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        if proc.is_alive():
            proc.kill()
            proc.join(10)
        receiver.close()
        proc.close()
