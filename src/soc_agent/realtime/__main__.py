"""Read-only common collector service; explicit private data and bounded batches."""

import argparse
import asyncio
import json
import os
import time
from pathlib import Path

from soc_agent.realtime.collectors import (
    CollectorUnavailable,
    LinuxJournalCollector,
    WindowsEventCollector,
)
from soc_agent.realtime.fixture import read_fixture
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.realtime.worker import composition, drain
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", choices=("journal", "windows", "fixture"), required=True)
    parser.add_argument(
        "--channel", choices=("System", "Application", "Security"), default="System"
    )
    parser.add_argument("--profile", choices=("DESKTOP", "SERVER"), default="DESKTOP")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--native-python", type=Path)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--batches", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1)
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 256 or args.batches < 1 or not 0.1 <= args.interval <= 60:
        parser.error("Explicit bounded batches and poll interval required")
    if os.name == "nt" and args.profile != "DESKTOP":
        parser.error("Windows Server unsupported")
    try:
        create_private_directory(args.directory)
        lock = args.directory / "pipeline.lock"
        try:
            create_private_file(lock)
        except FileExistsError:
            validate_file(lock)
        with exclusive_runtime_lock(lock):
            queue_path = args.directory / "ingestion.sqlite"
            queue = EventQueue(queue_path) if queue_path.exists() else EventQueue.create(queue_path)
            runtime_directory = args.directory / "runtime"
            path = runtime_directory / "external-validation.sqlite"
            store = (
                RuntimeGovernanceStore(path)
                if path.exists()
                else RuntimeGovernanceStore.create_isolated(runtime_directory)
            )
            application = composition(
                store,
                profile=args.profile,
                artifacts=args.artifacts,
                native_python=args.native_python,
            )
            collector = None
            if args.source == "journal":
                collector = LinuxJournalCollector()
            elif args.source == "windows":
                collector = WindowsEventCollector(args.channel)
            elif args.input is None:
                raise ValueError("Explicit fixture input required")
            queue.recover()
            # Drain committed work before collecting more. Shutdown leaves pending work durable.
            for batch in range(args.batches):
                asyncio.run(drain(queue, application))
                events = (
                    collector.poll(queue.cursor(collector.identity), limit=args.batch_size)
                    if collector
                    else read_fixture(args.input)
                )
                for event in events:
                    try:
                        queue.enqueue(
                            event, cursor_source=collector.identity if collector else None
                        )
                    except QueueFull:
                        asyncio.run(drain(queue, application))
                        queue.enqueue(
                            event, cursor_source=collector.identity if collector else None
                        )
                asyncio.run(drain(queue, application))
                if batch + 1 < args.batches:
                    time.sleep(args.interval)
            print(
                json.dumps(
                    {
                        "source": args.source,
                        "queue": queue.counts(),
                        "model_input": "NOT_INFERABLE" if collector else "explicit_fixture",
                        "provider_calls": 0,
                    }
                )
            )
            return 0
    except KeyboardInterrupt:
        print("Collector stopped; committed queue retained")
        return 0
    except CollectorUnavailable as error:
        print(str(error))  # Collector errors contain only fixed, sanitized category messages.
        return 1
    except (ValueError, OSError, StorageError):
        print("Read-only pipeline unavailable; no fallback; inspect sanitized queue state")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
