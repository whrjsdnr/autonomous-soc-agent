"""No privilege/capture: bounded snapshots, commit errors, durable completion."""

import errno
import threading

import pytest

from soc_agent.security_ai.ebpf.checkpoint import CheckpointFailure, CheckpointWriter


def test_full_writer_rejects_explicitly_without_dropping_or_reordering_submissions():
    started, release = threading.Event(), threading.Event()
    committed = []

    def persist(text, sha):
        started.set()
        assert release.wait(2)
        committed.append((text, sha))

    writer = CheckpointWriter(persist)
    try:
        writer.submit("first", "1")
        assert started.wait(1)
        writer.submit("second", "2")
        writer.submit("third", "3")
        with pytest.raises(CheckpointFailure, match="BACKPRESSURE"):
            writer.submit("rejected", "4")
        assert writer.snapshot()["outstanding"] == 3
        assert not writer.snapshot()["pending_is_durable"]
    finally:
        release.set()
        writer.close()
    assert committed == [("first", "1"), ("second", "2"), ("third", "3")]
    assert writer.rejected == 1 and writer.committed == 3


def test_commit_failure_stays_visible_and_does_not_claim_flush_success():
    def persist(*_):
        raise OSError(errno.EIO, "injected disk failure")

    writer = CheckpointWriter(persist)
    writer.submit("first", "1")
    with pytest.raises(CheckpointFailure, match="FLUSH_UNVERIFIED"):
        writer.flush()
    with pytest.raises(CheckpointFailure):
        writer.close()
    assert writer.committed == 0 and writer.failure["errno"] == errno.EIO
    assert not writer.worker.is_alive()
