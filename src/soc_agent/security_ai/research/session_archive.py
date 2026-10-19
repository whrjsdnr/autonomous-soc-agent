"""Explicit bounded evidence archival; no pruning, DB migration or inference replay.

A durable pending manifest precedes an atomic same-filesystem rename. Recovery
validates the unchanged source/destination before completing that transition.
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
from contextlib import ExitStack, closing
from pathlib import Path

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    validate_directory,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload

NAME = re.compile(r"session-[a-f0-9]{32}")
MAX_ARCHIVES, MAX_BYTES, MIN_FREE = 64, 2 * 1024**3, 256 * 1024**2
MAX_FILES = 4096


def _coordination_file(path):
    # Existing runtime coordination sentinels were created as 0644 inside a
    # private directory. They contain no evidence or credentials. Do not chmod
    # historical files; accept only empty, owned, non-writable-by-others files.
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
        or info.st_size != 0
    ):
        raise ValueError("ARCHIVE_UNSAFE_LOCK")
    return info


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read(path, limit=2 * 1024**2):
    info = validate_file(path)
    if info.st_size > limit:
        raise ValueError("ARCHIVE_MANIFEST_LIMIT")
    return json.loads(path.read_bytes())


def _write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2).encode())
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _entries(directory):
    pending, count = [directory], 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                if count > MAX_FILES:
                    raise ValueError("ARCHIVE_FILE_COUNT_LIMIT")
                path = Path(entry.path)
                yield path
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)


def inspect(directory: Path):
    """Read-only integrity inventory. An incomplete capture remains incomplete."""
    validate_directory(directory)
    if not NAME.fullmatch(directory.name):
        raise ValueError("ARCHIVE_SESSION_NAME_INVALID")
    identity = _read(directory / "session.json", 16384)
    session_id = identity.get("session_id")
    if not isinstance(session_id, str) or len(session_id) > 128 or not session_id:
        raise ValueError("ARCHIVE_SESSION_ID_INVALID")
    files, size, audit = {}, 0, None
    session_binding = "NOT_STARTED_RETAINED_ONLY"
    session_digest = content_digest_payload(identity)
    for path in _entries(directory):
        if path.is_symlink():
            raise ValueError("ARCHIVE_UNSAFE_FILE")
        if path.is_dir():
            validate_directory(path)
            continue
        info = (
            _coordination_file(path)
            if path.relative_to(directory).as_posix() == "runtime/writer.lock"
            else validate_file(path)
        )  # sockets, symlinks and foreign ownership fail closed
        size += info.st_size
        if len(files) >= MAX_FILES or size > MAX_BYTES:
            raise ValueError("ARCHIVE_SIZE_LIMIT")
        if path.name.endswith(("-wal", "-shm", "-journal")):
            raise ValueError("ARCHIVE_SQLITE_NOT_QUIESCENT")
        hashed = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024**2):
                hashed.update(block)
        files[path.relative_to(directory).as_posix()] = hashed.hexdigest()
        if path.suffix == ".sqlite":
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
                if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                    raise ValueError("ARCHIVE_SQLITE_INVALID")
                if path.name == "monitor.sqlite":
                    previous = "0" * 64
                    starts = 0
                    for index, (sequence, payload, digest) in enumerate(
                        db.execute(
                            "SELECT sequence,payload,digest FROM monitor_audit ORDER BY sequence"
                        ),
                        1,
                    ):
                        if index > 100000:
                            raise ValueError("ARCHIVE_AUDIT_LIMIT")
                        body = json.loads(payload)
                        if (
                            sequence != index
                            or body.get("sequence") != index
                            or body.get("previous") != previous
                            or content_digest_payload(body) != digest
                        ):
                            raise ValueError("ARCHIVE_AUDIT_INVALID")
                        if body.get("kind") == "STREAM_STARTED":
                            starts += 1
                            if (
                                starts > 1
                                or body["details"].get("session_digest") != session_digest
                            ):
                                raise ValueError("ARCHIVE_SESSION_AUDIT_MISMATCH")
                            session_binding = "SESSION_DIGEST_BOUND"
                        if body.get("kind") == "TOTAL_INTEGRITY_POLICY" and (
                            body["details"].get("session_digest") != session_digest
                            or body["details"].get("capture_session") != session_id
                        ):
                            raise ValueError("ARCHIVE_SESSION_AUDIT_MISMATCH")
                        previous = digest
                    audit = previous
    if audit is None:
        raise ValueError("ARCHIVE_AUDIT_MISSING")
    return {
        "contract": "soc-session-archive:v1",
        "directory": directory.name,
        "session_id": session_id,
        "session_digest": session_digest,
        "identity_binding": session_binding,
        "audit_digest": audit,
        "files": files,
        "bytes": size,
        "capture_validation": "PRESERVED_NOT_PROMOTED",
        "automatic_replay": False,
    }


class Archive:
    def __init__(self, root: Path):
        self.root = root.absolute()
        self.directory = self.root / "archives"

    def _setup(self):
        create_private_directory(self.root)
        create_private_directory(self.directory)
        if self.root.stat().st_dev != self.directory.stat().st_dev:
            raise ValueError("ARCHIVE_REQUIRES_ATOMIC_RENAME")

    def _manifest(self, path):
        value = _read(path)
        expected = value.pop("manifest_digest", None)
        if content_digest_payload(value) != expected or not NAME.fullmatch(
            value.get("directory", "")
        ):
            raise ValueError("ARCHIVE_MANIFEST_INVALID")
        return value

    def _verify(self, value, directory):
        if inspect(directory) != value:
            raise ValueError("ARCHIVE_CONTENT_MISMATCH")

    def verify(self, name):
        if not NAME.fullmatch(name):
            raise ValueError("ARCHIVE_SESSION_NAME_INVALID")
        value = self._manifest(self.directory / (name + ".json"))
        self._verify(value, self.directory / name)
        return value

    def _recover(self):
        for pending in sorted(self.directory.glob(".pending-session-*.json")):
            value = self._manifest(pending)
            name = value["directory"]
            source, destination = self.root / name, self.directory / name
            final = self.directory / (name + ".json")
            if final.exists() or source.exists() == destination.exists():
                raise ValueError("ARCHIVE_TRANSITION_AMBIGUOUS")
            directory = source if source.exists() else destination
            _coordination_file(directory / "runtime/writer.lock")
            with exclusive_runtime_lock(directory / "runtime/writer.lock"):
                self._verify(value, directory)
                if directory == source:
                    source.rename(destination)
                    _sync(self.root)
                    _sync(self.directory)
                pending.rename(final)
                _sync(self.directory)

    def status(self):
        if self.directory.is_symlink():
            raise ValueError("ARCHIVE_UNSAFE_DIRECTORY")
        if not self.directory.exists():
            return {
                "active": len(list(self.root.glob("session-*"))),
                "archived": [],
                "max_archives": MAX_ARCHIVES,
                "max_bytes": MAX_BYTES,
            }
        validate_directory(self.directory)
        manifests = sorted(self.directory.glob("session-*.json"))
        pending = sorted(self.directory.glob(".pending-session-*.json"))
        if len(manifests) + len(pending) > MAX_ARCHIVES:
            raise ValueError("ARCHIVE_CAPACITY_EXCEEDED")
        expected = {p.stem for p in manifests}
        expected.update(self._manifest(p)["directory"] for p in pending)
        present = {p.name for p in self.directory.glob("session-*") if p.is_dir()}
        if present - expected:
            raise ValueError("ARCHIVE_MANIFEST_MISSING")
        entries = []
        for path in manifests:
            value = self.verify(path.stem)
            entries.append(
                {key: value[key] for key in ("directory", "session_id", "audit_digest", "bytes")}
            )
        if len(entries) > MAX_ARCHIVES or sum(e["bytes"] for e in entries) > MAX_BYTES:
            raise ValueError("ARCHIVE_CAPACITY_EXCEEDED")
        return {
            "active": len(list(self.root.glob("session-*"))),
            "archived": entries,
            "pending": len(list(self.directory.glob(".pending-*.json"))),
            "max_archives": MAX_ARCHIVES,
            "max_bytes": MAX_BYTES,
        }

    def admission(self):
        """Preparation never bypasses damaged or interrupted archival evidence."""
        try:
            value = self.status()
            if value.get("pending", 0):
                raise ValueError("ARCHIVE_RECOVERY_REQUIRED")
        except (OSError, ValueError, sqlite3.Error) as error:
            raise ValueError("STREAM_ARCHIVE_INTEGRITY_BLOCKED") from error

    def archive_inactive(self, attached=None):
        self._setup()
        with exclusive_runtime_lock(self.root / "archive.lock"):
            self._recover()
            status = self.status()
            sources = [p for p in sorted(self.root.glob("session-*")) if p != attached]
            with ExitStack() as locks:
                plans = []
                for source in sources:
                    validate_directory(source)
                    _coordination_file(source / "runtime/writer.lock")
                    locks.enter_context(exclusive_runtime_lock(source / "runtime/writer.lock"))
                    value = inspect(source)
                    destination = self.directory / source.name
                    if destination.exists() or (self.directory / (source.name + ".json")).exists():
                        raise ValueError("ARCHIVE_IDENTITY_COLLISION")
                    if value["session_id"] in [e["session_id"] for e in status["archived"]] + [
                        p[1]["session_id"] for p in plans
                    ]:
                        raise ValueError("ARCHIVE_IDENTITY_COLLISION")
                    plans.append((source, value))
                if (
                    len(status["archived"]) + len(plans) > MAX_ARCHIVES
                    or sum(e["bytes"] for e in status["archived"])
                    + sum(v["bytes"] for _, v in plans)
                    > MAX_BYTES
                ):
                    raise ValueError("ARCHIVE_CAPACITY_EXCEEDED")
                if shutil.disk_usage(self.root).free < MIN_FREE:
                    raise ValueError("ARCHIVE_DISK_HEADROOM_REQUIRED")
                # All sessions verified before the first transition. Partial I/O failure
                # leaves a durable journal and never deletes source evidence.
                for source, value in plans:
                    pending = self.directory / (".pending-" + source.name + ".json")
                    _write(pending, {**value, "manifest_digest": content_digest_payload(value)})
                    self._verify(value, source)
                    source.rename(self.directory / source.name)
                    _sync(self.root)
                    _sync(self.directory)
                    pending.rename(self.directory / (source.name + ".json"))
                    _sync(self.directory)
            return self.status()
