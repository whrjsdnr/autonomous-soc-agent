"""Local Linux monitoring CLI; no IPC server and no security response commands."""

import argparse
import asyncio
import json
import signal
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.service import LinuxMonitor, initialize, open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.retention import MaintenanceLog
from soc_agent.state.evidence import utc_now


def status(directory: Path):
    store = RuntimeStore(directory.resolve())
    state = store.state()
    pipeline = open_pipeline(directory.resolve(), store.config)
    audit = MaintenanceLog(directory.resolve() / "collection-audit.sqlite", pipeline)
    audit.entries()
    jobs = store.jobs()
    queue = pipeline.queue.counts()
    heartbeat_age = (utc_now() - datetime.fromisoformat(state["heartbeat"])).total_seconds()
    active = state["state"] == "RUNNING" and 0 <= heartbeat_age <= max(
        5, store.config.investigation_seconds + store.config.poll_seconds * 3
    )
    collection_good = state["collector"] in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY")
    ready = active and collection_good and state["llm"] == "AVAILABLE"
    if store.config.assessment_mode == "READ_ONLY":
        ready = active and collection_good and state["last_error"] is None
    return {
        "runtime_state": state["state"],
        "health": "FAILED" if state["state"] == "FAILED" else "HEALTHY" if ready else "DEGRADED",
        "readiness": "READY" if ready else "NOT_READY",
        "uptime_seconds": max(
            0, (utc_now() - datetime.fromisoformat(state["started_at"])).total_seconds()
        )
        if state["started_at"]
        else None,
        "collector_state": state["collector"],
        "last_collection_time": state["last_collection"],
        "journal_cursor_health": state["cursor_health"],
        "queue_backlog": queue.get("PENDING", 0) + queue.get("CLAIMED", 0),
        "pending_investigations": jobs.get("PENDING", 0),
        "running_investigations": jobs.get("RUNNING", 0),
        "failed_investigations": jobs.get("FAILED", 0),
        "completed_read_only": jobs.get("DONE_READ_ONLY", 0),
        "completed_llm": jobs.get("DONE", 0),
        "last_investigation_time": state["last_investigation"],
        "llm_availability": state["llm"],
        "last_error": state["last_error"],
        "audit_store_health": "VERIFIED_LOCAL",
        "heartbeat_age_seconds": heartbeat_age,
        "inference_status": "NOT_INFERABLE",
        "write_disposition": "WRITE_DENIED",
        "real_os_handler_calls": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--repeated-failures", type=int, required=True)
    init.add_argument("--multiple-accounts", type=int, required=True)
    init.add_argument("--poll-seconds", type=float, default=2)
    init.add_argument("--assessment-mode", choices=("READ_ONLY", "REAL_LLM"), default="READ_ONLY")
    init.add_argument("--env-file", type=Path)
    start = sub.add_parser("start")
    start.add_argument("--duration-seconds", type=float)
    for command in ("stop", "status", "health", "readiness"):
        sub.add_parser(command)
    args = parser.parse_args()
    directory = args.directory.resolve()
    try:
        if args.command == "init":
            initialize(
                directory,
                RuntimeConfig(
                    incident_id=uuid4(),
                    repeated_failures=args.repeated_failures,
                    multiple_accounts=args.multiple_accounts,
                    poll_seconds=args.poll_seconds,
                    assessment_mode=args.assessment_mode,
                    env_file=args.env_file.resolve() if args.env_file else None,
                ),
            )
            print(json.dumps({"initialized": True, "response": "DISABLED"}))
        elif args.command == "stop":
            RuntimeStore(directory).request_stop()
            print(json.dumps({"stop_requested": True}))
        elif args.command == "start":

            async def start_runtime():
                monitor = LinuxMonitor(directory)
                loop = asyncio.get_running_loop()
                for signum in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(signum, monitor.request_stop)
                try:
                    await monitor.run(duration_seconds=args.duration_seconds)
                finally:
                    for signum in (signal.SIGINT, signal.SIGTERM):
                        loop.remove_signal_handler(signum)

            asyncio.run(start_runtime())
            print(json.dumps(status(directory)))
        else:
            print(json.dumps(status(directory)))
    except (ValueError, OSError, RuntimeError) as error:
        print(
            json.dumps(
                {"health": "FAILED", "readiness": "NOT_READY", "error": type(error).__name__}
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
