"""Explicit precomputed common-event fixture; never pretends to be an OS collector."""

import os
import stat
from pathlib import Path

from soc_agent.local_events import explicit_path
from soc_agent.realtime.models import CommonEvent


def read_fixture(path: Path) -> list[CommonEvent]:
    path = explicit_path(path)
    for component in (path, *path.parents):
        if getattr(component.stat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Reparse fixture path rejected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 4 * 1024 * 1024:
        raise ValueError("Bounded regular fixture required")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Fixture identity changed")
        events = []
        consumed = 0
        for _ in range(257):
            line = stream.readline(262145)
            if not line:
                return events
            consumed += len(line)
            if len(line) > 262144 or len(events) == 256 or consumed > before.st_size:
                raise ValueError("Fixture limit exceeded")
            event = CommonEvent.model_validate_json(line)
            if event.platform != "validated_fixture":
                raise ValueError("File source cannot forge native collection provenance")
            events.append(event)
    raise ValueError("Fixture record limit exceeded")
