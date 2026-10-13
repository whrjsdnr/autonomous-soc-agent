"""Bounded read-only Linux auth intake. Isolated private test directory only."""

import argparse
import json
from pathlib import Path
from uuid import UUID

from soc_agent.realtime.queue import EventQueue
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--incident", type=UUID, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()
    directory = args.directory
    if not directory.is_absolute() or not 1 <= args.limit <= 256:
        parser.error("Explicit absolute isolated directory and bounded limit required")
    if directory.exists() and not args.resume:
        parser.error("Existing directory not adopted without explicit --resume")
    if args.resume and not directory.is_dir():
        parser.error("Resume directory unavailable")
    if not args.resume:
        create_private_directory(directory, exist_ok=False)
    lock = directory / "auth-intake.lock"
    if lock.exists():
        validate_file(lock)
    else:
        create_private_file(lock)
    with exclusive_runtime_lock(lock):
        queue_path, store_path = directory / "queue.sqlite", directory / "sources.sqlite"
        queue = EventQueue(queue_path) if args.resume else EventQueue.create(queue_path)
        options = {"allowed_lateness_seconds": 60, "max_future_skew_seconds": 5}
        store = (
            OperationalSourceStore(store_path, **options)
            if args.resume
            else OperationalSourceStore.create(store_path, **options)
        )
        pipeline = AuthenticationPipeline(queue, store, args.incident)
        queue.recover()  # lock retained throughout recovery and drain
        collector = LinuxAuthenticationCollector()
        collected = pipeline.collect(collector, limit=args.limit)
        mapped = unknown = late = 0
        for _ in range(queue.capacity * queue.retry_limit):
            receipt = pipeline.step()
            if receipt == "IDLE":
                break
            if receipt == "NOT_INFERABLE":
                unknown += 1
            else:
                mapped += 1
                late += receipt.admission.status == "LATE_QUARANTINED"
        else:
            raise ValueError("AUTH_DRAIN_LIMIT_REACHED")
        summary = {
            "platform": "WSL/Linux; separate host not inferred",
            "collected": collected,
            "mapped_authentication": mapped,
            "not_inferable_records": unknown,
            "late_quarantined": late,
            "authentication_windows": len(store.windows(args.incident)),
            "queue_counts": queue.counts(),
            "cursor_retained": queue.cursor(collector.identity) is not None,
            "inference_status": "NOT_INFERABLE",
            "write_disposition": "WRITE_DENIED",
        }
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
