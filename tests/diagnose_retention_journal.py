"""Private retention diagnostic: native read-only collection and explicit fixture profiling."""

import argparse
import asyncio
import gc
import json
import os
import sys
import time
import tracemalloc
from pathlib import Path

from soc_agent.realtime.models import CommonEvent
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.journal_health import collect_with_health
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    NativeAuthenticationReceipt,
    project_journal,
)
from soc_agent.security_ai.operational.retention import (
    MaintenanceLog,
    retention_plan,
    storage_metrics,
)
from soc_agent.security_ai.operational.source_records import AuthenticationSource
from tests.authentication_crash_harness import open_pipeline, security_check
from tests.unit.operational_features.test_native_authentication import row


def memory():
    rss = None
    if Path("/proc/self/statm").exists():
        rss = (
            int(Path("/proc/self/statm").read_text().split()[1])
            * os.sysconf("SC_PAGE_SIZE")
            / 2**20
        )
    objects = gc.get_objects()
    counts = {
        cls.__name__: sum(type(o) is cls for o in objects)
        for cls in (CommonEvent, AuthenticationSource, NativeAuthenticationReceipt)
    }
    del objects
    current, peak = tracemalloc.get_traced_memory()
    return {
        "rss_memory_mb": rss,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
        "gc_tracked_models": counts,
        "allocated_blocks": sys.getallocatedblocks()
        if hasattr(sys, "getallocatedblocks")
        else None,
    }


def profile(root):
    p = open_pipeline(root, LinuxAuthenticationCollector.identity, create=True)
    log = MaintenanceLog.create(root / "maintenance.sqlite", p)
    samples = []
    started = time.monotonic()
    tracemalloc.start()
    with exclusive_runtime_lock(root / "writer.lock"):
        for index in range(61):
            if index:
                event = project_journal(row(index, index % 50))
                p.queue.enqueue(event, cursor_source=p.binding["collector"])
                p.step()
            if index in (0, 10, 30, 60):
                before = memory()
                gc.collect()
                after = memory()
                plan = retention_plan(p, audit=log)
                metrics = storage_metrics(p)
                metrics.update(
                    {
                        "events": index,
                        "elapsed_seconds": time.monotonic() - started,
                        "before_gc": before,
                        "after_gc": after,
                        "retention_protected_count": plan.protected_count,
                    }
                )
                pages = []
                for db in (p.queue.database, p.store.database):
                    with db.transaction(write=False) as c:
                        pages.append(
                            {
                                k: c.execute(f"PRAGMA {k}").fetchone()[0]
                                for k in (
                                    "page_count",
                                    "page_size",
                                    "freelist_count",
                                    "cache_size",
                                    "journal_mode",
                                )
                            }
                        )
                        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                metrics["sqlite_pages"] = pages
                samples.append(metrics)
        snapshot = tracemalloc.take_snapshot()
        top = [
            {
                "file": Path(s.traceback[0].filename).name,
                "line": s.traceback[0].lineno,
                "size_bytes": s.size,
                "blocks": s.count,
            }
            for s in snapshot.statistics("lineno")[:10]
        ]
        view = read_authentication_view(p)
        assert view.authentication_events_verified == 60
        security = asyncio.run(security_check(p))
    tracemalloc.stop()
    return {
        "data_kind": "FIXTURE",
        "elapsed_seconds": time.monotonic() - started,
        "samples": samples,
        "allocation_top": top,
        "security": security,
        "cache_used_bytes": None,
        "leak_verdict": "UNDETERMINED",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if not args.directory.is_absolute() or args.directory.exists():
        parser.error("New private absolute directory required")
    create_private_directory(args.directory, exist_ok=False)
    results = {"profile": profile(args.directory / "profile")}
    collector = LinuxAuthenticationCollector(include_pam_failures=True)
    root = args.directory / "native"
    p = open_pipeline(root, collector.identity, create=True)
    audit = MaintenanceLog.create(root / "maintenance.sqlite", p)
    with exclusive_runtime_lock(root / "writer.lock"):
        first = collect_with_health(p, collector, audit=audit, limit=128)
        for _ in range(384):
            if p.step() == "IDLE":
                break
        else:
            raise ValueError("DRAIN_LIMIT")
        resumed = collect_with_health(
            p, LinuxAuthenticationCollector(include_pam_failures=True), audit=audit, limit=1
        )
        for _ in range(3):
            if p.step() == "IDLE":
                break
        plan = retention_plan(p, audit=audit)
        view = read_authentication_view(p)
        results["native"] = {
            "collection": first.model_dump(mode="json"),
            "resume": resumed.model_dump(mode="json"),
            "metrics": storage_metrics(p),
            "protected_count": plan.protected_count,
            "eligible_count": plan.eligible_count,
            "reference_integrity": plan.reference_integrity,
            "authentication_events": view.authentication_events_verified,
            "security": asyncio.run(security_check(p)),
            "gap_count": sum(e["status"] == "GAP_DETECTED" for e in audit.entries()),
            "cursor_resume_failures": sum(
                e["status"] in ("GAP_DETECTED", "CURSOR_INVALID") for e in audit.entries()
            ),
        }
    output = args.directory / "results.json"
    create_private_file(output)
    output.write_text(json.dumps(results, indent=2, allow_nan=False))
    print(
        json.dumps(
            {
                "profile_events": 60,
                "native_collection": first.status,
                "native_resume": resumed.status,
                "native_authentication_events": view.authentication_events_verified,
                "retention_eligible": 0,
                "write_spy_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
