"""Atomic compressed Native record segments, anchored in the existing service audit.

Compaction removes only committed active copies after a verified segment and index
are durable. Historical Root/Native campaign evidence and service audit are untouched.
"""

import gzip
import hashlib
import json
import os
from pathlib import Path

from soc_agent.review.persistence.secure_storage import create_private_directory


def persist(directory: Path, records: list[dict]) -> tuple[str, str]:
    target = directory / "segments"
    create_private_directory(target)
    body = b"".join(json.dumps(record, sort_keys=True).encode() + b"\n" for record in records)
    raw_pin = hashlib.sha256(body).hexdigest()
    encoded = gzip.compress(body, mtime=0)
    pin = hashlib.sha256(encoded).hexdigest()
    final = target / (pin + ".jsonl.gz")
    if final.exists():
        if hashlib.sha256(final.read_bytes()).hexdigest() != pin:
            raise ValueError("CONTINUOUS_SEGMENT_CHANGED")
        return pin, raw_pin
    temporary = target / (pin + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, final)
        fd = os.open(target, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        # Partial temporary files stay uncommitted evidence and are never read.
        raise
    return pin, raw_pin


def read(directory: Path, pin: str, raw_pin: str):
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise ValueError("CONTINUOUS_SEGMENT_IDENTITY")
    from soc_agent.security_ai.research.environment import read_local

    encoded = read_local(directory / "segments" / (pin + ".jsonl.gz"), 16 * 1024**2)
    if hashlib.sha256(encoded).hexdigest() != pin:
        raise ValueError("CONTINUOUS_SEGMENT_CHANGED")
    # Bound decompression, not merely compressed file size.
    import io

    with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as stream:
        body = stream.read(16 * 1024**2 + 1)
    if len(body) > 16 * 1024**2 or hashlib.sha256(body).hexdigest() != raw_pin:
        raise ValueError("CONTINUOUS_SEGMENT_CONTENT")
    return [json.loads(line) for line in body.splitlines()]
