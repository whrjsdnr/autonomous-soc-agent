"""SIGKILL only the owned crash-harness child; never OS services or user processes."""

import multiprocessing
import os
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.linux_runtime.findings import correlate
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import initialize, open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.native_authentication import project_journal


def child(directory, point, channel, nonce):
    from pathlib import Path

    root = Path(directory)
    with exclusive_runtime_lock(root / "writer.lock"):
        store = RuntimeStore(root)
        if point == "DETECTION_COMMIT":
            pipeline = open_pipeline(root, store.config)
            for finding in correlate(pipeline, store.config):
                store.put(finding)
        else:
            store.claim()
        channel.send((os.getpid(), nonce, point))
        channel.recv()  # Parent owns the child and only kills it after the lock handshake.


@pytest.mark.parametrize("point", ["DETECTION_COMMIT", "INVESTIGATION_CLAIM"])
def test_owned_process_crash_keeps_findings_recoverable(tmp_path, point):
    root = tmp_path / "private"
    from uuid import UUID

    store = initialize(
        root, RuntimeConfig(incident_id=UUID(int=11), repeated_failures=2, multiple_accounts=2)
    )
    pipeline = open_pipeline(root, store.config)
    for i in range(2):
        pipeline.queue.enqueue(
            project_journal(
                row(i + 1, i, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2"),
                include_pam_failures=True,
            )
        )
        pipeline.step()
    if point == "INVESTIGATION_CLAIM":
        for finding in correlate(pipeline, store.config):
            store.put(finding)
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe(duplex=True)
    nonce = str(uuid4())
    process = context.Process(target=child, args=(str(root), point, sender, nonce))
    process.start()
    sender.close()
    try:
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        restored = RuntimeStore(root)
        with exclusive_runtime_lock(root / "writer.lock"):
            restored.recover()
            assert restored.jobs() == {"PENDING": 2}
            assert restored.claim() is not None
            for database in (restored.database, pipeline.queue.database, pipeline.store.database):
                with database.transaction(write=False) as c:
                    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        restored.verify_audit()
    finally:
        if process.is_alive():
            process.kill()
            process.join(10)
        process.close()
        parent.close()
