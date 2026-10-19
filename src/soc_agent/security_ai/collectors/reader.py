"""One bounded batch; open old inode drains before rotation. Checkpoint after commit."""

import hashlib
import os
import stat
from pathlib import Path


class LogReader:
    def __init__(self, path: Path, cursor: dict | None = None):
        self.path = path
        self.file = None
        self.cursor = cursor
        self.offset = 0
        self.hasher = hashlib.sha256()
        self.rotations = 0

    def _open(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        self.file = os.fdopen(fd, "rb")
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            self.close()
            raise ValueError("ZEEK_LOG_NOT_REGULAR")
        if self.cursor:
            c = self.cursor
            if (st.st_dev, st.st_ino) != (c["device"], c["inode"]):
                raise ValueError("ZEEK_ROTATION_RECOVERY_UNVERIFIED")
            if st.st_size < c["offset"]:
                raise ValueError("ZEEK_LOG_TRUNCATED")
            self.offset = c["offset"]
            remaining = self.offset
            while remaining:
                b = self.file.read(min(65536, remaining))
                if not b:
                    raise ValueError("ZEEK_LOG_TRUNCATED")
                self.hasher.update(b)
                remaining -= len(b)
            if self.hasher.hexdigest() != c["prefix_digest"]:
                raise ValueError("ZEEK_LOG_PREFIX_TAMPERED")
            self.cursor = None

    def read(self, maximum=32) -> tuple[list[bytes], dict | None]:
        if not 1 <= maximum <= 256:
            raise ValueError("ZEEK_QUEUE_BOUND")
        if self.file is None:
            if not self.path.exists():
                return [], None
            self._open()
        st = os.fstat(self.file.fileno())
        if st.st_size > 8 * 1024**2:
            raise ValueError("ZEEK_LOG_SIZE_BUDGET")
        if st.st_size < self.offset:
            raise ValueError("ZEEK_LOG_TRUNCATED")
        # Detect rewritten committed prefixes, including same-size rewrites.
        if self.offset:
            position = self.file.tell()
            self.file.seek(0)
            h = hashlib.sha256()
            remaining = self.offset
            while remaining:
                chunk = self.file.read(min(65536, remaining))
                if not chunk:
                    raise ValueError("ZEEK_LOG_TRUNCATED")
                h.update(chunk)
                remaining -= len(chunk)
            self.file.seek(position)
            if h.digest() != self.hasher.digest():
                raise ValueError("ZEEK_LOG_PREFIX_TAMPERED")
        rows = []
        for _ in range(maximum):
            before = self.file.tell()
            value = self.file.readline(16385)
            if not value:
                break
            if len(value) > 16384:
                raise ValueError("ZEEK_RECORD_BOUND")
            if not value.endswith(b"\n"):
                self.file.seek(before)
                break
            self.hasher.update(value)
            self.offset = self.file.tell()
            rows.append(value)
        current = self.path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino) and not rows:
            if self.file.tell() != st.st_size:
                raise ValueError("ZEEK_ROTATION_WITH_PARTIAL_RECORD")
            self.file.close()
            self.file = None
            self.offset = 0
            self.hasher = hashlib.sha256()
            self.rotations += 1
            if self.rotations > 16:
                raise ValueError("ZEEK_LOG_ROTATION_BUDGET")
            return self.read(maximum)
        if not rows:
            return [], None
        return rows, dict(
            device=st.st_dev,
            inode=st.st_ino,
            offset=self.offset,
            prefix_digest=self.hasher.hexdigest(),
        )

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None

    def finish(self):
        if self.file is not None and self.offset != os.fstat(self.file.fileno()).st_size:
            raise ValueError("ZEEK_PARTIAL_RECORD_ON_CLOSE")
