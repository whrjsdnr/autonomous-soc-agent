"""Linux build-input guard; no authentication, network or privileged operations.

Builds belong in a separate export. Watching starts before the initial snapshot;
even a write followed by restoration invalidates the build. This is change
detection, not a filesystem lock against an adversarial concurrent writer.
"""

import ctypes
import hashlib
import os
import stat
import struct
from pathlib import Path

IGNORED = {"__pycache__", ".pytest_cache", ".ruff_cache"}
MASK = 0x00000002 | 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080
MASK |= 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800
EVENT = struct.Struct("iIII")


def snapshot(root: Path) -> dict[str, str]:
    """Hash regular files, rejecting symlinks and a changing held file snapshot."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in IGNORED)
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("SOURCE_SYMLINK_REJECTED")
        for name in sorted(files):
            path = Path(directory) / name
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("SOURCE_REGULAR_FILE_REQUIRED")
                digest = hashlib.sha256()
                while body := os.read(fd, 65536):
                    digest.update(body)
                after = os.fstat(fd)
                current = path.lstat()
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(
                    getattr(before, key) != getattr(after, key)
                    or getattr(after, key) != getattr(current, key)
                    for key in fields
                ):
                    raise ValueError("SOURCE_CHANGED_DURING_READ")
                result[str(path.relative_to(root))] = digest.hexdigest()
            finally:
                os.close(fd)
    return dict(sorted(result.items()))


class SourceGuard:
    """Bounded inotify guard for one build input tree; outputs must be elsewhere."""

    def __init__(self, root: Path):
        self.root = root.absolute()
        self.fd = -1
        self.watches: dict[int, str] = {}
        self.start: dict[str, str] = {}
        self.events: list[dict[str, str | int]] = []

    def __enter__(self):
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("SOURCE_ROOT_DIRECTORY_REQUIRED")
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes, init.restype = [ctypes.c_int], ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes, add.restype = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32], ctypes.c_int
        self.fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "SOURCE_WATCH_INIT")
        try:
            for directory, dirs, _ in os.walk(self.root, followlinks=False):
                dirs[:] = sorted(name for name in dirs if name not in IGNORED)
                if len(self.watches) >= 4096:
                    raise ValueError("SOURCE_WATCH_LIMIT")
                # IN_ONLYDIR | IN_DONT_FOLLOW: never follow a replaced symlink.
                wd = add(self.fd, os.fsencode(directory), MASK | 0x01000000 | 0x02000000)
                if wd < 0:
                    raise OSError(ctypes.get_errno(), "SOURCE_WATCH_ADD")
                self.watches[wd] = str(Path(directory).relative_to(self.root))
            self.start = snapshot(self.root)
            self.check()
            return self
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def check(self) -> dict[str, str]:
        end = snapshot(self.root)
        changed = bool(self.events)  # A rejected build cannot become valid by checking again.
        total = 0
        while True:
            try:
                body = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not body:
                raise ValueError("SOURCE_WATCH_CLOSED")
            total += len(body)
            if total > 1048576:
                raise ValueError("SOURCE_WATCH_EVENT_LIMIT")
            offset = 0
            while offset < len(body):
                wd, mask, _, length = EVENT.unpack_from(body, offset)
                offset += EVENT.size
                name = os.fsdecode(body[offset : offset + length].split(b"\0", 1)[0])
                offset += length
                # Overflow/ignored/self-move have no ordinary filename. Fail closed.
                if name not in IGNORED or mask & (0x00004000 | 0x00008000):
                    changed = True
                    if len(self.events) < 32:
                        self.events.append(
                            dict(directory=self.watches.get(wd, "UNKNOWN"), name=name, mask=mask)
                        )
        if changed or end != self.start:
            raise ValueError("SOURCE_CHANGED_DURING_BUILD")
        return end

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.check()
        finally:
            os.close(self.fd)
            self.fd = -1
