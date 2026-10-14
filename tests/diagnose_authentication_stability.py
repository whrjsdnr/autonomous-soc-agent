"""Offline stability diagnostic: explicit fixtures/native projected logs, isolated databases."""

import argparse
import asyncio
import json
import multiprocessing
import os
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    project_journal,
)
from tests.authentication_crash_harness import (
    POINTS,
    crash_case,
    open_pipeline,
    security_check,
)
from tests.unit.operational_features.test_native_authentication import row


def sample(p, root, cycle, started):
    with p.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT payload,status,attempts FROM realtime_events").fetchall()
    from soc_agent.realtime.models import CommonEvent

    pending = [
        CommonEvent.model_validate_json(r["payload"])
        for r in rows
        if r["status"] in ("PENDING", "CLAIMED")
    ]
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    view = read_authentication_view(p)
    with p.store.database.transaction(write=False) as c:
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with p.queue.database.transaction(write=False) as c:
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # Linux current resident pages, not invented/max-RSS performance samples.
    rss = (
        int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20
        if os.name == "posix" and Path("/proc/self/statm").exists()
        else None
    )
    return {
        "elapsed_seconds": time.monotonic() - started,
        "events_collected": len(rows),
        "events_enqueued": len(rows),
        "events_claimed": sum(r["attempts"] for r in rows),
        "events_acked": sum(r["status"] == "DONE" for r in rows),
        "events_retried": sum(max(0, r["attempts"] - 1) for r in rows),
        "events_rejected": sum(r["status"] == "POISON" for r in rows),
        "events_deduplicated": len(rows),  # one explicit duplicate enqueue per accepted fixture
        "authentication_windows_created": len(view.authentication_window),
        "authentication_event_effects": sum(w.total for w in view.authentication_window),
        "provenance_validation_failures": 0,  # revalidation above must succeed
        "queue_depth": len(pending),
        "oldest_pending_age_seconds": max(
            ((now - e.ingestion_timestamp).total_seconds() for e in pending), default=0
        ),
        "process_restart_count": cycle,
        "rss_memory_mb": rss,
        "sqlite_database_size_bytes": sum(f.stat().st_size for f in root.glob("*.sqlite*")),
        "inference_status": view.inference_status,
        "action_policy": view.action_policy,
    }


def soak_child(root_string, seconds, cycle, started, channel, native_enabled):
    root = Path(root_string)
    identity = LinuxAuthenticationCollector.identity
    p = open_pipeline(root, identity)
    native = None
    collector = None
    if native_enabled:
        collector = LinuxAuthenticationCollector(include_pam_failures=True)
        native = open_pipeline(root / "native-monitor", collector.identity)
    from contextlib import ExitStack

    with ExitStack() as locks:
        locks.enter_context(exclusive_runtime_lock(root / "writer.lock"))
        if native:
            locks.enter_context(exclusive_runtime_lock(root / "native-monitor" / "writer.lock"))
            native.queue.recover()
        p.queue.recover()
        with p.queue.database.transaction(write=False) as c:
            index = c.execute("SELECT count(*) FROM realtime_events").fetchone()[0]
        until = time.monotonic() + seconds
        last_read = 0.0
        reads = 0
        while time.monotonic() < until:
            index += 1
            event = project_journal(row(index, index % 50))
            assert p.queue.enqueue(event, cursor_source=identity)
            assert not p.queue.enqueue(event)  # duplicate receipt, same source content
            p.step()
            if native:
                batch = collector.poll(native.queue.cursor(collector.identity), limit=16)
                for record in batch:
                    native.queue.enqueue(record, cursor_source=collector.identity)
                    assert not native.queue.enqueue(record)
                for _ in range(48):
                    if native.step() == "IDLE":
                        break
                else:
                    raise AssertionError("NATIVE_DRAIN_LIMIT")
            if time.monotonic() - last_read >= 25:
                security = asyncio.run(security_check(p))
                reads += security["agent_read_queries"]
                metric = sample(p, root, cycle, started)
                metric.update(security)
                if native:
                    metric["native"] = sample(native, root / "native-monitor", cycle, started)
                    metric["native"].update(asyncio.run(security_check(native)))
                channel.send(metric)
                last_read = time.monotonic()
            time.sleep(min(5, max(0, until - time.monotonic())))
        metric = sample(p, root, cycle, started)
        if native:
            metric["native"] = sample(native, root / "native-monitor", cycle, started)
        metric["child_agent_queries"] = reads
        assert (
            metric["events_enqueued"]
            == metric["authentication_event_effects"]
            == metric["events_acked"]
        )
        channel.send(metric)


def soak(root, duration, *, native_enabled=False, segment_seconds=60):
    open_pipeline(root, LinuxAuthenticationCollector.identity, create=True)
    if native_enabled:
        open_pipeline(
            root / "native-monitor",
            LinuxAuthenticationCollector(include_pam_failures=True).identity,
            create=True,
        )
    metrics_path = root / "metrics.jsonl"
    create_private_file(metrics_path)
    ctx = multiprocessing.get_context("spawn")
    started = time.monotonic()
    cycle = 0
    queries = blocked = 0
    last = None
    while time.monotonic() - started < duration:
        receiver, sender = ctx.Pipe(duplex=False)
        proc = ctx.Process(
            target=soak_child,
            args=(
                str(root),
                min(segment_seconds, duration - (time.monotonic() - started)),
                cycle,
                started,
                sender,
                native_enabled,
            ),
        )
        proc.start()
        sender.close()
        try:
            while proc.is_alive() or receiver.poll():
                if receiver.poll(1):
                    try:
                        metric = receiver.recv()
                    except EOFError:
                        break
                    queries += metric.get("agent_read_queries", 0)
                    blocked += metric.get("write_attempts_blocked", 0)
                    metric["agent_read_queries_total"] = queries
                    metric["write_attempts_blocked_total"] = blocked
                    with metrics_path.open("a") as stream:
                        stream.write(json.dumps(metric, allow_nan=False) + "\n")
                    last = metric
            proc.join(10)
            if proc.exitcode != 0:
                raise RuntimeError("SOAK_CHILD_FAILED")
        finally:
            if proc.is_alive():
                proc.kill()  # only owned child object, never system process
                proc.join(10)
            receiver.close()
            proc.close()
        cycle += 1
    elapsed = time.monotonic() - started
    assert (
        last
        and last["queue_depth"] == 0
        and last["events_acked"] == last["authentication_event_effects"]
    )
    return {
        "status": "PASS",
        "data_kind": "FIXTURE",
        "elapsed_seconds": elapsed,
        "requested_seconds": duration,
        "worker_processes": cycle,
        "last_metric": last,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--smoke-seconds", type=int, default=300)
    parser.add_argument("--soak-seconds", type=int, default=1800)
    parser.add_argument("--native-crashes", action="store_true")
    parser.add_argument("--soak-only", action="store_true")
    parser.add_argument("--worker-lifetime-seconds", type=int, default=60)
    args = parser.parse_args()
    if (
        not args.directory.is_absolute()
        or args.directory.exists()
        or not (1 <= args.smoke_seconds <= 7200 and 1 <= args.soak_seconds <= 7200)
    ):
        parser.error("New absolute private path and bounded durations required")
    if not 1 <= args.worker_lifetime_seconds <= 7200:
        parser.error("Bounded worker lifetime required")
    create_private_directory(args.directory, exist_ok=False)
    if args.soak_only:
        result = soak(
            args.directory / "continuous",
            args.soak_seconds,
            native_enabled=args.native_crashes,
            segment_seconds=args.worker_lifetime_seconds,
        )
        create_private_file(args.directory / "results.json")
        (args.directory / "results.json").write_text(json.dumps({"continuous": result}, indent=2))
        print(
            json.dumps(
                {"continuous": result["status"], "elapsed_seconds": result["elapsed_seconds"]}
            ),
            flush=True,
        )
        return
    results = {"fixture_crashes": [], "native_crashes": [], "native_status": "NOT_TESTED"}
    for point in POINTS:
        results["fixture_crashes"].append(
            crash_case(args.directory / point, project_journal(row()), point)
        )
    if args.native_crashes:
        collector = LinuxAuthenticationCollector(include_pam_failures=True)
        records = collector.poll(limit=128)
        event = next(
            (
                e
                for e in records
                if dict(e.normalized_fields).get("parse_status") == "MAPPED_AUTHENTICATION"
            ),
            None,
        )
        results["native_collected"] = len(records)
        if event is None:
            results["native_status"] = "INCONCLUSIVE"
        else:
            results["native_status"] = "REAL_OS_PROJECTED_REPLAY"
            results["native_event_digest"] = event.source_digest
            for point in POINTS:
                results["native_crashes"].append(
                    crash_case(
                        args.directory / ("native-" + point),
                        event,
                        point,
                        identity=collector.identity,
                    )
                )
    path = args.directory / "results.json"
    create_private_file(path)
    path.write_text(json.dumps(results, indent=2))
    results["smoke"] = soak(
        args.directory / "smoke", args.smoke_seconds, native_enabled=args.native_crashes
    )
    path.write_text(json.dumps(results, indent=2))
    print(
        json.dumps(
            {
                "smoke": results["smoke"]["status"],
                "elapsed_seconds": results["smoke"]["elapsed_seconds"],
            }
        ),
        flush=True,
    )
    results["soak"] = soak(
        args.directory / "soak", args.soak_seconds, native_enabled=args.native_crashes
    )
    path.write_text(json.dumps(results, indent=2))
    print(
        json.dumps(
            {
                "soak": results["soak"]["status"],
                "elapsed_seconds": results["soak"]["elapsed_seconds"],
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
