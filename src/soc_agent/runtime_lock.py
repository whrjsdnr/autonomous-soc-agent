"""Nonblocking single-writer coordination; never an authority or storage-policy override."""

import ctypes
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from soc_agent.review.persistence.secure_storage import guard_directory


class Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", ctypes.c_uint32),
        ("offset_high", ctypes.c_uint32),
        ("event", ctypes.c_void_p),
    ]


@contextmanager
def _posix_lock(path: Path) -> Iterator[None]:
    import fcntl

    with path.open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def _windows_lock(path: Path) -> Iterator[None]:
    from soc_agent.review.persistence.windows_storage import NativeWin32, verify

    api = NativeWin32()
    pointer = ctypes.POINTER(Overlapped)
    api.kernel.LockFileEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        pointer,
    ]
    api.kernel.LockFileEx.restype = ctypes.c_int32
    api.kernel.UnlockFileEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        pointer,
    ]
    api.kernel.UnlockFileEx.restype = ctypes.c_int32
    api._no_impersonation()
    with api.descriptor(directory=False) as attributes:
        # OPEN_ALWAYS never truncates. No delete sharing pins the coordination file.
        # Descriptor is applied at creation; an existing file is verified, never repaired.
        handle = api.kernel.CreateFileW(
            str(path), 0xC0020080, 3, ctypes.byref(attributes), 4, 0x00200080, None
        )
    if handle == ctypes.c_void_p(-1).value:
        raise OSError("Runtime lock file unavailable; no fallback")
    try:
        verify(api.snapshot(handle), api.user, directory=False)
        overlap = Overlapped()  # Offset zero, synchronous handle, no event.
        # Every writer contends for byte zero, including on an empty file (beyond EOF).
        # This is a coordination sentinel, not an arbitrary file-I/O locking interface.
        api._check(api.kernel.LockFileEx(handle, 3, 0, 1, 0, ctypes.byref(overlap)))
        try:
            yield
        finally:
            api._check(api.kernel.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlap)))
    finally:
        api.kernel.CloseHandle(handle)


def _backend(platform: str):
    if platform == "posix":
        return _posix_lock
    if platform == "nt":
        return _windows_lock
    raise OSError("Runtime locking unsupported on this platform; no fallback")


@contextmanager
def exclusive_runtime_lock(path: Path) -> Iterator[None]:
    backend = _backend(os.name)
    # Existing secure-storage policy applies; Windows ancestor handles stay pinned.
    with guard_directory(path.parent):
        with backend(path):
            yield
