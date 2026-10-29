"""Explicit Replay recovery into a fresh directory; source evidence is read-only.

Uses the existing Store, EventQueue recovery and tombstones. Never restores Native
authority, requeues a dead letter, resets attempts or changes the original files.
"""

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

from soc_agent.continuous.store import Store
from soc_agent.review.persistence.secure_storage import create_private_directory, validate_directory
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import JOB


def inspect_queue(directory: Path) -> dict:
    store = Store(directory)
    state = store.state()  # Existing full audit-chain and detail validation.
    store.require_streaming_schema()
    if store.config.source != "NATIVE_SERVICE":
        store.retained()  # Includes the existing checkpoint digest/sequence check.
    counts = store.queue.counts()
    with store.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT * FROM realtime_events ORDER BY rowid LIMIT 100001").fetchall()
        if len(rows) > 100000:
            raise ValueError("CONTINUOUS_RECOVERY_QUEUE_BOUND")
        cursors = [row[0] for row in c.execute("SELECT source FROM realtime_cursors")]
    kinds = {}
    for row in rows:
        event = store.queue._decode(row)
        job = JOB.validate_json(read_local(store.input_path(event), 1024**2))
        if digest(job.model_dump(mode="json")) != dict(event.normalized_fields)["job_digest"]:
            raise ValueError("CONTINUOUS_INPUT_CHANGED")
        kinds[job.kind] = kinds.get(job.kind, 0) + 1
    for cursor in cursors:
        store.queue.cursor(cursor)
    return dict(
        state=state["state"],
        cleanup=state["cleanup"],
        counts=counts,
        kinds=kinds,
        pending=counts.get("PENDING", 0),
        in_flight=counts.get("CLAIMED", 0),
        acknowledged=counts.get("DONE", 0),
        dead_letter=counts.get("POISON", 0),
        failed=counts.get("POISON", 0),
        observed_duplicates=state.get("metrics", {}).get("duplicates", 0),
        store_id=str(store.database.store_id),
        cursor_sources=len(cursors),
        audit="VERIFIED",
        checkpoint="VERIFIED" if store.config.source != "NATIVE_SERVICE" else "NATIVE_SEPARATE",
    )


def inventory(directory: Path) -> dict[str, str]:
    validate_directory(directory)
    files = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("CONTINUOUS_RECOVERY_UNSAFE_FILE")
        if path.name.endswith(("-wal", "-journal", "-shm")) and info.st_size:
            raise ValueError("CONTINUOUS_RECOVERY_QUIESCENT_SQLITE_REQUIRED")
        total += info.st_size
        if total > 1024**3:
            raise ValueError("CONTINUOUS_RECOVERY_STORAGE_BOUND")
        with path.open("rb") as stream:
            files[str(path.relative_to(directory))] = hashlib.file_digest(
                stream, "sha256"
            ).hexdigest()
    return files


def clone_replay(source: Path, target: Path) -> dict:
    from soc_agent.continuous.cli import code_identity

    source, target = source.absolute(), target.absolute()
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError("CONTINUOUS_RECOVERY_FRESH_SEPARATE_TARGET_REQUIRED")
    validate_directory(source)
    lock = os.open(source / "service.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = inventory(source)
        summary = inspect_queue(source)
        original = Store(source)
        if original.config.source == "NATIVE_SERVICE":
            raise ValueError("CONTINUOUS_NATIVE_RECOVERY_REQUIRES_SEPARATE_REVIEW")
        if summary["state"] != "STOPPED" or summary["cleanup"] != "VERIFIED":
            raise ValueError("CONTINUOUS_RECOVERY_VERIFIED_STOP_REQUIRED")
        if (
            hashlib.sha256(read_local(original.config.input_file, 64 * 1024**2)).hexdigest()
            != original.config.input_sha256
        ):
            raise ValueError("CONTINUOUS_RECOVERY_SOURCE_SHA")
        create_private_directory(target, exist_ok=False)
        for name in before:
            relative = Path(name)
            if relative.name.endswith(".lock") or relative.name in (
                "code-identity",
                "observation.json",
            ):
                continue
            destination = target / relative
            create_private_directory(destination.parent)
            if relative.suffix == ".sqlite":
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                with sqlite3.connect(
                    (source / relative).as_uri() + "?mode=ro&immutable=1", uri=True
                ) as old:
                    with sqlite3.connect(destination) as new:
                        old.backup(new)
            else:
                body = read_local(source / relative, 64 * 1024**2)
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(body)
                    output.flush()
                    os.fsync(output.fileno())
        store = Store(target)
        # Validate every job before rebinding this Replay-only copy to current code.
        inspect_queue(target)
        for path in (target / "inputs").glob("*.json"):
            job = JOB.validate_json(read_local(path, 1024**2))
            if job.kind in ("native_checkpoint", "tcx_analysis"):
                raise ValueError("CONTINUOUS_RECOVERY_NATIVE_JOB_FORBIDDEN")
        state = original.state()
        lineage = dict(
            contract="soc-replay-recovery-copy:v1",
            source=str(source),
            files=before,
            original_state=state,
            queue=summary,
            previous_code=read_local(source / "code-identity", 128).decode(),
            current_code=code_identity(),
            source_unchanged=True,
            native_authority=False,
            dead_letters_requeued=False,
        )
        if inventory(source) != before:
            raise ValueError("CONTINUOUS_RECOVERY_SOURCE_CHANGED_DURING_COPY")
        (target / "recovery-source.json").write_text(json.dumps(lineage, indent=2))
        (target / "recovery-source.json").chmod(0o600)
        (target / "code-identity").write_text(code_identity())
        (target / "code-identity").chmod(0o600)
        store.event("CONTINUOUS_REPLAY_COPY_VALIDATED", dict(lineage=digest(lineage)))
        store.update(
            dict(
                state="STOPPED",
                cleanup="VERIFIED",
                collection_live=False,
                source=store.config.source,
                queue=store.queue.counts(),
                recovery_source=str(source),
                baseline_counts=summary["counts"],
                recent_results=[],
                collector="STOPPED",
                worker="STOPPED",
            )
        )
        return dict(
            status="RECOVERY_COPY_NOT_STARTED",
            runtime=str(target),
            source_unchanged=True,
            queue=summary,
            native_authority="NOT_GRANTED",
        )
    finally:
        os.close(lock)
