"""Verified SQLite backup snapshots. Never delete audit or infer crash completion.

Quiescent ordinary service archival keeps input/output evidence and queue tombstones
available. Rotating a claimed/pending queue or an unknown cleanup is forbidden.
"""

import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
from uuid import uuid4

from soc_agent.continuous.store import Store
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def verify(directory: Path):
    body = read_local(directory / "manifest.json", 4 * 1024**2)
    manifest = json.loads(body)
    if directory.name != digest(manifest):
        raise ValueError("CONTINUOUS_ARCHIVE_IDENTITY")
    for name, pin in manifest["files"].items():
        path = directory / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink():
            raise ValueError("CONTINUOUS_ARCHIVE_PATH")
        if hashlib.sha256(read_local(path, 1024**3)).hexdigest() != pin:
            raise ValueError("CONTINUOUS_ARCHIVE_CHANGED")
    return manifest


def archive(directory: Path):
    with exclusive_runtime_lock(directory / "service.lock"):
        store = Store(directory)
        state = store.state()
        counts = store.queue.counts()
        if (
            state["state"] != "STOPPED"
            or state["cleanup"] != "VERIFIED"
            or any(counts.get(k, 0) for k in ("PENDING", "CLAIMED"))
        ):
            raise ValueError("CONTINUOUS_ARCHIVE_QUIESCENCE_REQUIRED")
        target = directory / "archives"
        create_private_directory(target)
        stage = target / (".pending-" + str(uuid4()))
        create_private_directory(stage)
        try:
            for name in ("service.sqlite", "queue.sqlite", "authentication/journal-queue.sqlite"):
                if not (directory / name).exists():
                    continue
                if (directory / name).is_symlink():
                    raise ValueError("CONTINUOUS_ARCHIVE_SYMLINK_REJECTED")
                dest = stage / name
                create_private_directory(dest.parent)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                with sqlite3.connect(dest) as output:
                    with sqlite3.connect(
                        (directory / name).as_uri() + "?mode=ro", uri=True
                    ) as source:
                        source.backup(output)
            if (directory / "code-identity").exists():
                shutil.copyfile(directory / "code-identity", stage / "code-identity")
            for name in ("inputs", "analysis", "segments"):
                if (directory / name).exists():
                    if (directory / name).is_symlink() or any(
                        p.is_symlink() for p in (directory / name).rglob("*")
                    ):
                        raise ValueError("CONTINUOUS_ARCHIVE_SYMLINK_REJECTED")
                    shutil.copytree(directory / name, stage / name, symlinks=False)
            files = {}
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    path.chmod(0o600)
                    files[str(path.relative_to(stage))] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
            manifest = dict(
                contract="soc-continuous-archive:v1",
                files=files,
                queue_counts=counts,
                source=store.config.input_sha256,
                source_mode=store.config.source,
                store_id=str(store.database.store_id),
            )
            pin = digest(manifest)
            (stage / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
            (stage / "manifest.json").chmod(0o600)
            for path in stage.rglob("*"):
                if path.is_file():
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
            final = target / pin
            if final.exists():
                verify(final)
                shutil.rmtree(stage)
            else:
                os.rename(stage, final)
            fd = os.open(target, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            verify(final)
            store.event("CONTINUOUS_ARCHIVE_VERIFIED", dict(archive=pin))
            # Evidence and tombstones remain in place. An explicit external
            # retention/export policy is required before active payload removal.
            return dict(
                status="ARCHIVED_VERIFIED",
                identity=pin,
                path=str(final),
                destructive_retention=False,
            )
        except BaseException:
            # A partially written archive is preserved as .pending evidence; it
            # is never published or accepted as a verified archive.
            store.event("CONTINUOUS_ARCHIVE_FAILED", dict(stage=stage.name))
            raise


def restore(archived: Path, target: Path):
    manifest = verify(archived)
    if manifest.get("source_mode") not in ("PCAP_REPLAY", "JSONL_REPLAY"):
        raise ValueError("CONTINUOUS_NATIVE_RESTORE_REQUIRES_SEPARATE_REVIEW")
    if not {"service.sqlite", "queue.sqlite", "code-identity"} <= manifest["files"].keys():
        raise ValueError("CONTINUOUS_RESTORE_MISSING_REQUIRED_FILES")
    create_private_directory(target, exist_ok=False)
    try:
        for name in manifest["files"]:
            destination = target / name
            create_private_directory(destination.parent)
            shutil.copyfile(archived / name, destination)
            destination.chmod(0o600)
        create_private_directory(target / "inputs")
        create_private_directory(target / "results")
        store = Store(target)
        store.require_streaming_schema()
        store.retained()
        store.auxiliary()
        store.segments()
        store.event("CONTINUOUS_RESTORED_NOT_STARTED", dict(archive=archived.name))
        return dict(status="RESTORED_NOT_STARTED", directory=str(target), authority="REPLAY_ONLY")
    except BaseException:
        # Keep the unstarted partial restoration for diagnosis; never activate it.
        raise
