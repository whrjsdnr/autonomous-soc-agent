"""Narrow storage permission boundary; unsupported platforms never skip verification."""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class StorageSecurityError(ValueError):
    """Sanitized failure of the storage security contract."""


class UnsupportedSecureStorage(StorageSecurityError):
    """A verified platform implementation is required before storage may be touched."""


@dataclass(frozen=True)
class FileIdentity:
    st_dev: int
    st_ino: int


def require_supported_platform() -> None:
    if os.name not in ("posix", "nt"):
        raise UnsupportedSecureStorage("Secure storage unavailable on this platform; no fallback")


def _windows():
    from soc_agent.review.persistence.windows_storage import WindowsStorage

    return WindowsStorage()


def create_private_directory(path: Path, *, exist_ok: bool = True) -> None:
    require_supported_platform()
    if os.name == "nt":
        _windows().create_directory(path, exist_ok=exist_ok)
    else:
        path.mkdir(mode=0o700, parents=True, exist_ok=exist_ok)
        validate_directory(path)


def create_private_file(path: Path) -> None:
    require_supported_platform()
    if os.name == "nt":
        _windows().create_file(path)
    else:
        descriptor = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        os.close(descriptor)


@contextmanager
def guard_directory(path: Path) -> Iterator[None]:
    require_supported_platform()
    if os.name == "nt":
        with _windows().guard(path):
            yield
    else:
        validate_directory(path)
        yield


def validate_directory(path: Path) -> None:
    require_supported_platform()
    if os.name == "nt":
        _windows().validate_directory(path)
        return
    # A private directory cannot protect a path redirected through a symlink.
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise StorageSecurityError("Storage directory must not use symlinks")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise StorageSecurityError("Database directory must be private (mode 0700)")
    if info.st_uid != os.geteuid():
        raise StorageSecurityError("Storage directory must be owned by the runtime user")


def validate_file(path: Path) -> os.stat_result | FileIdentity:
    require_supported_platform()
    if os.name == "nt":
        return _windows().validate_file(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise StorageSecurityError(
            "Database and sidecars must be regular private files (mode 0600), not symlinks"
        )
    if info.st_uid != os.geteuid():
        raise StorageSecurityError("Storage file must be owned by the runtime user")
    return info


def validate_database_files(path: Path) -> tuple[int, int]:
    validate_directory(path.parent)
    info = validate_file(path)
    validate_sidecars(path)
    return info.st_dev, info.st_ino


def validate_sidecars(path: Path) -> None:
    """Check known single-database SQLite sidecars without opening or deleting them."""
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            validate_file(path.with_name(path.name + suffix))
        except FileNotFoundError:
            # SQLite removes transient sidecars normally; absence is not a benign signal.
            continue
