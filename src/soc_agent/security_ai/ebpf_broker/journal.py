"""Single-writer append-only bounded fixture journal; never an authorization store."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from soc_agent.security_ai.research.models import digest


class Journal:
    def __init__(self, path: Path, plan_digest: str, limit: int):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.plan_digest, self.limit = plan_digest, limit
        self.sequence, self.previous, self.bytes = 0, "0" * 64, 0

    def record(self, kind: str, **details) -> None:
        value = dict(
            sequence=self.sequence + 1,
            previous=self.previous,
            plan_digest=self.plan_digest,
            source="PHASE_B1_FIXTURE_NOT_NATIVE",
            timestamp=datetime.now(UTC).isoformat(),
            kind=kind,
            details=details,
        )
        value["digest"] = digest(value)
        body = (json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(body) > 16384 or self.bytes + len(body) > self.limit or self.sequence >= 1024:
            raise ValueError("BROKER_AUDIT_BUDGET")
        if os.write(self.fd, body) != len(body):
            raise ValueError("BROKER_AUDIT_PARTIAL_WRITE")
        os.fsync(self.fd)
        self.bytes += len(body)
        self.sequence, self.previous = value["sequence"], value["digest"]

    def close(self) -> None:
        os.close(self.fd)


def recover(path: Path, plan_digest: str) -> dict:
    if path.is_symlink() or path.stat().st_size > 1048576:
        raise ValueError("BROKER_AUDIT_BOUND")
    failed = False
    previous, count, last_owner, clean, exited = "0" * 64, 0, None, False, False
    with path.open() as f:
        for line in f:
            if len(line) > 16384 or not line.endswith("\n"):
                raise ValueError("BROKER_AUDIT_PARTIAL")
            row = json.loads(line)
            actual = row.pop("digest")
            count += 1
            if (
                count > 1024
                or row["sequence"] != count
                or row["previous"] != previous
                or row["plan_digest"] != plan_digest
                or row["source"] != "PHASE_B1_FIXTURE_NOT_NATIVE"
                or digest(row) != actual
            ):
                raise ValueError("BROKER_AUDIT_INTEGRITY_FAILED")
            previous = actual
            if row["kind"] in {"BROKER_ERROR", "CLEANUP_UNVERIFIED", "BROKER_FAILURE_CLASSIFIED"}:
                failed = True
            if row["kind"] == "ATTACH_REQUESTED":
                clean = False
            if row["kind"] == "ATTACH_VERIFIED":
                last_owner = row["details"]["ownership"]
            if row["kind"] == "CLEANUP_VERIFIED":
                clean = True
            if row["kind"] == "CLEANUP_UNVERIFIED":
                clean = False
            exited = row["kind"] == "BROKER_EXITED"
    if not count:
        raise ValueError("BROKER_AUDIT_EMPTY")
    return dict(
        audit_digest=previous,
        events=count,
        state="CLOSED" if clean and exited and not failed else "ERROR",
        cleanup_status="FIXTURE_VERIFIED" if clean and exited else "CLEANUP_UNVERIFIED",
        last_ownership=last_owner,
        authentication_restored=False,
        automatic_attach=False,
        automatic_inference=False,
        user_review_required=not (clean and exited),
    )
