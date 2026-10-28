"""Read-only, bounded UTF-8 JSONL replay. No OS log access or follow/rotation semantics."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import TypeAdapter, ValidationError

if TYPE_CHECKING:
    from soc_agent.ingestion.models import Event

MAX_EVENT_BYTES = 128 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_LINES = 1000


class LocalSourceError(ValueError):
    """Sanitized local source error; never includes a path or input value."""


def explicit_path(path: Path) -> Path:
    """Require explicit absolute paths without traversal or existing symlink components."""
    if (
        not path.is_absolute()
        or ".." in path.parts
        or any(p.is_symlink() for p in (path, *path.parents))
    ):
        raise LocalSourceError("Explicit absolute non-symlink path required")
    return path


@dataclass(frozen=True)
class InputIssue:
    line_number: int
    reason: str


class LocalJSONLSource:
    """Finite replay of a regular file; descriptor closed on EOF, error or cancellation.

    Preserve the typed envelope source/event ID and canonical ingestion provenance.
    Paths/raw contents are never included in diagnostics. Appends past the initial
    byte boundary fail closed; replay has no implicit tail, rewind or retry.
    """

    def __init__(self, path: Path):
        self.path = explicit_path(path)

    def events(self) -> Iterator[Event | InputIssue]:
        from soc_agent.ingestion.models import Event

        try:
            before = self.path.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
                raise LocalSourceError("Regular file within input size limit required")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(self.path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise LocalSourceError("Source changed during open")
                consumed = 0
                for number in range(1, MAX_LINES + 2):
                    line = stream.readline(MAX_EVENT_BYTES + 1)
                    if not line:
                        return
                    consumed += len(line)
                    if (
                        number > MAX_LINES
                        or len(line) > MAX_EVENT_BYTES
                        or consumed > before.st_size
                    ):
                        raise LocalSourceError("Input replay limit exceeded; stopped")
                    if not line.strip():
                        continue
                    try:
                        yield TypeAdapter(Event).validate_json(line)
                    except ValidationError:
                        yield InputIssue(number, "Invalid event schema or encoding")
        except OSError:
            raise LocalSourceError("Local source unavailable") from None
