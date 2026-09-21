"""Strict package inventory and bounded, no-follow reads. Hashes are not signatures."""

import hashlib
import json
import os
import stat
from pathlib import Path

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
FILES = frozenset(
    {"manifest.json", "metadata.json", "model/model.json", "preprocessing/profile.json"}
)
DIRECTORIES = frozenset({"model", "preprocessing"})


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def strict_json(value: bytes) -> object:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = item
        return result

    def invalid(value):
        raise ValueError("Nonfinite JSON value")

    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid package JSON") from error


def read_package(path: Path) -> dict[str, bytes]:
    # Open each directory component relative to an already opened directory FD.
    # This rejects symlinks in ancestors as well as inside the package.
    absolute = Path(os.path.abspath(path))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if set(os.listdir(fd)) != {"manifest.json", "metadata.json", *DIRECTORIES}:
            raise ValueError("Unexpected or missing package entries")
        values = {}
        for name in sorted(FILES):
            parent = fd
            nested = None
            try:
                parts = name.split("/")
                if len(parts) == 2:
                    nested = os.open(
                        parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                    parent = nested
                    expected = {"model.json"} if parts[0] == "model" else {"profile.json"}
                    if set(os.listdir(parent)) != expected:
                        raise ValueError("Unexpected or missing nested entries")
                file_fd = os.open(
                    parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
                with os.fdopen(file_fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                        raise ValueError("Unsupported or oversized package file")
                    value = stream.read(MAX_FILE_BYTES + 1)
                    if len(value) > MAX_FILE_BYTES:
                        raise ValueError("Oversized package file")
                    values[name] = value
            finally:
                if nested is not None:
                    os.close(nested)
        if sum(map(len, values.values())) > MAX_PACKAGE_BYTES:
            raise ValueError("Package exceeds total size budget")
        return values
    except OSError as error:
        raise ValueError("Invalid package path or file") from error
    finally:
        os.close(fd)
