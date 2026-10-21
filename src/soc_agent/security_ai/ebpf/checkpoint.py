"""Bounded, ordered FULL-transaction checkpoint writer; never owns packet records."""

import queue
import sqlite3
import threading
import time
from collections.abc import Callable

from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError


class CheckpointFailure(ValueError):
    pass


class CheckpointWriter:
    def __init__(self, persist: Callable[[str, str], None]):
        self.persist = persist
        self.queue: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=2)
        self.stop = threading.Event()
        self.submitted = self.committed = self.rejected = 0
        self.max_ns = self.total_ns = 0
        self.failure: dict | None = None
        self.worker = threading.Thread(target=self._run, name="tcx-checkpoint-writer", daemon=True)
        self.worker.start()

    def submit(self, text: str, sha: str) -> None:
        if self.failure or self.stop.is_set():
            raise CheckpointFailure("EBPF_CHECKPOINT_WRITER_UNAVAILABLE")
        if len(text.encode()) > 16384:
            raise CheckpointFailure("EBPF_CHECKPOINT_SIZE")
        # Count admission before notifying the writer so a fast commit cannot
        # temporarily appear ahead of submitted snapshots in status reads.
        self.submitted += 1
        try:
            self.queue.put_nowait((text, sha))
        except queue.Full as exc:
            self.submitted -= 1
            self.rejected += 1
            raise CheckpointFailure("EBPF_CHECKPOINT_BACKPRESSURE") from exc

    def _run(self) -> None:
        while not self.stop.is_set() or not self.queue.empty():
            try:
                text, sha = self.queue.get(timeout=0.02)
            except queue.Empty:
                continue
            started = time.perf_counter_ns()
            try:
                if self.failure is None:
                    self.persist(text, sha)
                    self.committed += 1
            except (OSError, sqlite3.Error, StorageError, CommitOutcomeUnknown, ValueError) as exc:
                original = exc
                while original.__cause__ is not None:
                    original = original.__cause__
                self.failure = self.failure or dict(
                    category=type(exc).__name__,
                    errno=original.errno if isinstance(original, OSError) else None,
                    sqlite_errorcode=getattr(original, "sqlite_errorcode", None),
                    commit_outcome="UNKNOWN" if isinstance(exc, CommitOutcomeUnknown) else "FAILED",
                )
            finally:
                elapsed = time.perf_counter_ns() - started
                self.max_ns = max(self.max_ns, elapsed)
                self.total_ns += elapsed
                self.queue.task_done()

    def flush(self, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.005)
        if self.failure or self.queue.unfinished_tasks or self.committed != self.submitted:
            raise CheckpointFailure("EBPF_CHECKPOINT_FLUSH_UNVERIFIED")

    def close(self) -> None:
        self.stop.set()
        self.worker.join(timeout=5)
        if self.worker.is_alive():
            raise CheckpointFailure("EBPF_CHECKPOINT_WORKER_UNVERIFIED")
        self.flush(timeout=0)

    def snapshot(self) -> dict:
        return dict(
            capacity=2,
            max_snapshot_bytes=16384,
            submitted=self.submitted,
            committed=self.committed,
            rejected=self.rejected,
            outstanding=self.submitted - self.committed,
            failure=self.failure,
            max_commit_ns=self.max_ns,
            total_commit_ns=self.total_ns,
            worker_alive=self.worker.is_alive(),
            durability="FULL_SQLITE_COMMIT_ONLY",
            pending_is_durable=False,
        )
