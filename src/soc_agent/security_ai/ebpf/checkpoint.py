"""Bounded, ordered FULL-transaction checkpoint writer; never owns packet records."""

import json
import queue
import sqlite3
import threading
import time
from collections.abc import Callable

from soc_agent.review.persistence.models import CommitOutcomeUnknown, StorageError

MAX_CHECKPOINT_BYTES = 16384
MAX_RECEIPTS = 1024  # Existing FlowAssembly finalized-flow bound.
MAX_EXPANDED_BYTES = 8 * 1024**2  # Existing per-session disk budget.


def _json_text(value: object) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("EBPF_CHECKPOINT_ENCODING") from exc


def _summary_shape(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    if "candidate_eligibility" in value:
        rows = value["candidate_eligibility"]
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError("EBPF_CHECKPOINT_ENCODING")
        if len(rows) > MAX_RECEIPTS:
            raise ValueError("EBPF_CHECKPOINT_SIZE")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("EBPF_CHECKPOINT_ENCODING")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("EBPF_CHECKPOINT_ENCODING")


def _shared_fields(rows: list[dict]) -> dict:
    return (
        {
            key: rows[0][key]
            for key in sorted(rows[0])
            if all(key in row and _json_text(row[key]) == _json_text(rows[0][key]) for row in rows)
        }
        if rows
        else {}
    )


def _factor_rows(rows: list[dict]) -> dict:
    shared = _shared_fields(rows)
    remaining = [{key: item for key, item in row.items() if key not in shared} for row in rows]
    # Lifecycle counters/timestamps differ, but their authority and Window
    # context often repeat. Never merge distinct observations or reorder rows.
    nested = [row.get("lifecycle") for row in remaining]
    lifecycle = (
        _shared_fields(nested) if nested and all(isinstance(x, dict) for x in nested) else {}
    )
    if lifecycle:
        remaining = [
            row | {"lifecycle": {k: v for k, v in row["lifecycle"].items() if k not in lifecycle}}
            for row in remaining
        ]
    return dict(shared=shared, lifecycle_shared=lifecycle, rows=remaining)


def _restore_rows(group: object) -> list[dict]:
    if (
        not isinstance(group, dict)
        or set(group) != {"shared", "lifecycle_shared", "rows"}
        or not isinstance(group["shared"], dict)
        or not isinstance(group["lifecycle_shared"], dict)
        or not isinstance(group["rows"], list)
        or len(group["rows"]) > MAX_RECEIPTS
    ):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    shared, lifecycle, rows = group["shared"], group["lifecycle_shared"], group["rows"]
    if lifecycle and "lifecycle" in shared:
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    # Bound the worst-case expansion before constructing repeated objects.
    if (len(_json_text(shared).encode()) + len(_json_text(lifecycle).encode())) * len(rows) + len(
        _json_text(rows).encode()
    ) > MAX_EXPANDED_BYTES:
        raise ValueError("EBPF_CHECKPOINT_SIZE")
    restored = []
    for row in rows:
        if not isinstance(row, dict) or shared.keys() & row.keys():
            raise ValueError("EBPF_CHECKPOINT_ENCODING")
        if lifecycle:
            if (
                not isinstance(row.get("lifecycle"), dict)
                or lifecycle.keys() & row["lifecycle"].keys()
            ):
                raise ValueError("EBPF_CHECKPOINT_ENCODING")
            row = row | dict(lifecycle=lifecycle | row["lifecycle"])
        restored.append(shared | row)
    return restored


def encode_checkpoint(value: dict) -> str:
    """Losslessly factor repeated RCA context; never omit a candidate receipt."""
    _summary_shape(value)
    text = _json_text(value)
    if len(text.encode()) <= MAX_CHECKPOINT_BYTES:
        return text  # Legacy JSON shape; canonical keys and actual UTF-8 bytes.
    rows = value.get("candidate_eligibility")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RECEIPTS:
        raise ValueError("EBPF_CHECKPOINT_SIZE")
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    shared = _shared_fields(rows)
    summary = {key: item for key, item in value.items() if key != "candidate_eligibility"}
    encoded = dict(
        checkpoint_encoding="SHARED_RCA_V1",
        summary=summary,
        shared=shared,
        rows=[{key: item for key, item in row.items() if key not in shared} for row in rows],
    )
    text = _json_text(encoded)
    tail = value.get("feature_tail")
    if (
        isinstance(tail, list)
        and len(tail) <= MAX_RECEIPTS
        and all(isinstance(x, dict) for x in tail)
    ):
        compact = _json_text(
            dict(
                checkpoint_encoding="SHARED_CONTEXT_V2",
                summary={k: v for k, v in summary.items() if k != "feature_tail"},
                candidates=_factor_rows(rows),
                feature_tail=_factor_rows(tail),
            )
        )
        if len(compact.encode()) < len(text.encode()):
            text = compact
    if len(text.encode()) > MAX_CHECKPOINT_BYTES:
        raise ValueError("EBPF_CHECKPOINT_SIZE")
    # The same bounded decoder must accept what we persist.
    decode_checkpoint(text)
    return text


def decode_checkpoint(text: str) -> dict:
    if len(text.encode()) > MAX_CHECKPOINT_BYTES:
        raise ValueError("EBPF_CHECKPOINT_SIZE")
    value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    if "checkpoint_encoding" not in value:
        _summary_shape(value)
        return value  # Historical evidence is read as-is, never rewritten.
    if value["checkpoint_encoding"] == "SHARED_CONTEXT_V2":
        if (
            set(value) != {"checkpoint_encoding", "summary", "candidates", "feature_tail"}
            or not isinstance(value["summary"], dict)
            or {"candidate_eligibility", "feature_tail"} & value["summary"].keys()
        ):
            raise ValueError("EBPF_CHECKPOINT_ENCODING")
        restored = value["summary"] | dict(
            candidate_eligibility=_restore_rows(value["candidates"]),
            feature_tail=_restore_rows(value["feature_tail"]),
        )
        _summary_shape(restored)
        if len(_json_text(restored).encode()) > MAX_EXPANDED_BYTES:
            raise ValueError("EBPF_CHECKPOINT_SIZE")
        return restored
    if (
        set(value) != {"checkpoint_encoding", "summary", "shared", "rows"}
        or value["checkpoint_encoding"] != "SHARED_RCA_V1"
        or not isinstance(value["summary"], dict)
        or "candidate_eligibility" in value["summary"]
        or not isinstance(value["shared"], dict)
        or not isinstance(value["rows"], list)
        or not 1 <= len(value["rows"]) <= MAX_RECEIPTS
    ):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    shared, rows = value["shared"], value["rows"]
    if any(not isinstance(row, dict) or shared.keys() & row.keys() for row in rows):
        raise ValueError("EBPF_CHECKPOINT_ENCODING")
    # Bound expansion before allocating repeated contexts; no compression bomb.
    if len(_json_text(shared).encode()) * len(rows) + len(text.encode()) > MAX_EXPANDED_BYTES:
        raise ValueError("EBPF_CHECKPOINT_SIZE")
    return value["summary"] | dict(candidate_eligibility=[shared | row for row in rows])


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
        if len(text.encode()) > MAX_CHECKPOINT_BYTES:
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
            max_snapshot_bytes=MAX_CHECKPOINT_BYTES,
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
