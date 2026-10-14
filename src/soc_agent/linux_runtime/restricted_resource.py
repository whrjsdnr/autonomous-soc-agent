"""One registered private marker, accessed using pinned directory/file descriptors.

The runtime UID is trusted. This detects replacement and conflicting content; it
does not sandbox malicious code or root racing trusted code in the same UID.
"""

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from soc_agent.linux_runtime.restricted_models import (
    AVAILABLE,
    QUARANTINED,
    MarkerOutput,
    ResourceRegistration,
)
from soc_agent.review.persistence.secure_storage import validate_directory


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def private(info: os.stat_result, *, directory: bool = False) -> None:
    if (
        info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("RESTRICTED_RESOURCE_SECURITY_REJECTED")


class TestResource:
    __test__ = False

    def __init__(self, directory: Path):
        self.directory = directory

    @contextmanager
    def _base(self) -> Iterator[tuple[int, Callable[[], None]]]:
        """Pin every path component: O_NOFOLLOW on the leaf alone is insufficient."""
        if not self.directory.is_absolute() or ".." in self.directory.parts:
            raise ValueError("RESTRICTED_RUNTIME_PATH_REJECTED")
        validate_directory(self.directory)
        expected = identity(self.directory.lstat())
        descriptors: list[int] = []
        chain: list[tuple[int, str, int]] = []
        try:
            base = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(base)
            for name in self.directory.parts[1:]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
                descriptors.append(child)
                chain.append((base, name, child))
                base = child

            def verify() -> None:
                private(os.fstat(base), directory=True)
                if identity(os.fstat(base)) != expected:
                    raise ValueError("RESTRICTED_RESOURCE_REPLACED")
                for parent, name, child in chain:
                    if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(
                        os.fstat(child)
                    ):
                        raise ValueError("RESTRICTED_RESOURCE_REPLACED")

            verify()
            yield base, verify
            verify()
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def create(self) -> ResourceRegistration:
        """Explicit offline TEST mode initialization. Never adopt an existing path."""
        with self._base() as (base, verify_base):
            os.mkdir("test-resources", mode=0o700, dir_fd=base)
            expected_root = os.stat("test-resources", dir_fd=base, follow_symlinks=False)
            private(expected_root, directory=True)
            root = os.open(
                "test-resources", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base
            )
            try:
                if identity(os.fstat(root)) != identity(expected_root):
                    raise ValueError("RESTRICTED_RESOURCE_REPLACED")
                verify_base()
                fd = os.open(
                    "marker",
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root,
                )
                try:
                    private(os.fstat(fd))
                    if os.write(fd, AVAILABLE) != len(AVAILABLE):
                        raise OSError("RESTRICTED_SHORT_WRITE")
                    os.fsync(fd)
                    registration = ResourceRegistration(
                        runtime_location_digest=digest(os.fsencode(self.directory)),
                        runtime_identity=identity(os.fstat(base)),
                        root_identity=identity(os.fstat(root)),
                        marker_identity=identity(os.fstat(fd)),
                    )
                finally:
                    os.close(fd)
                os.fsync(root)
                os.fsync(base)
                verify_base()
                with self.opened(registration):
                    pass  # Validate the same registered names before publishing registration.
                return registration
            finally:
                os.close(root)

    @contextmanager
    def opened(self, registration: ResourceRegistration, *, writable: bool = False):
        if registration.runtime_location_digest != digest(os.fsencode(self.directory)):
            raise ValueError("RESTRICTED_RUNTIME_LOCATION_REPLACED")
        with self._base() as (base, verify_base):
            with self._opened(base, verify_base, registration, writable=writable) as value:
                yield value

    @contextmanager
    def _opened(
        self,
        base: int,
        verify_base: Callable[[], None],
        registration: ResourceRegistration,
        *,
        writable: bool = False,
    ):
        descriptors = []
        try:
            root = os.open(
                "test-resources", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base
            )
            descriptors.append(root)
            access = os.O_RDWR if writable else os.O_RDONLY
            fd = os.open("marker", access | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            descriptors.append(fd)

            def verify():
                verify_base()
                for descriptor, expected, directory in (
                    (base, registration.runtime_identity, True),
                    (root, registration.root_identity, True),
                    (fd, registration.marker_identity, False),
                ):
                    info = os.fstat(descriptor)
                    private(info, directory=directory)
                    if identity(info) != expected:
                        raise ValueError("RESTRICTED_RESOURCE_REPLACED")
                if (
                    identity(self.directory.lstat()) != registration.runtime_identity
                    or identity(os.stat("test-resources", dir_fd=base, follow_symlinks=False))
                    != registration.root_identity
                    or identity(os.stat("marker", dir_fd=root, follow_symlinks=False))
                    != registration.marker_identity
                ):
                    raise ValueError("RESTRICTED_RESOURCE_REPLACED")

            verify()
            yield fd, verify
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

    def probe(self, registration: ResourceRegistration) -> str:
        with self.opened(registration) as (fd, verify):
            value = os.pread(fd, 65, 0)
            verify()
            if value not in (AVAILABLE, QUARANTINED):
                raise ValueError("RESTRICTED_RESOURCE_CONTENT_REJECTED")
            return digest(value)

    def change(
        self,
        registration: ResourceRegistration,
        before: str,
        after: bytes,
        *,
        before_write: Callable[[], None] | None = None,
    ) -> MarkerOutput:
        if after not in (AVAILABLE, QUARANTINED):
            raise ValueError("RESTRICTED_MARKER_VALUE_REJECTED")
        with self.opened(registration, writable=True) as (fd, verify):
            value = os.pread(fd, 65, 0)
            if value not in (AVAILABLE, QUARANTINED) or digest(value) != before or value == after:
                raise ValueError("RESTRICTED_RESOURCE_STATE_CONFLICT")
            verify()
            if before_write is not None:
                before_write()
                verify()
            if os.pwrite(fd, after, 0) != len(after):
                raise OSError("RESTRICTED_SHORT_WRITE")
            os.ftruncate(fd, len(after))
            os.fsync(fd)
            verify()
            result = os.pread(fd, 65, 0)
            if result != after:
                raise ValueError("RESTRICTED_RESOURCE_POSTCONDITION_FAILED")
            return MarkerOutput(before_digest=before, after_digest=digest(result))
