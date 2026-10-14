"""Local Linux monitoring CLI; no IPC server and no security response commands."""

import argparse
import asyncio
import json
import signal
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from soc_agent.approval.errors import ApprovalError
from soc_agent.execution.errors import ExecutionError
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.response_simulation import RuntimeResponseSimulation
from soc_agent.linux_runtime.service import LinuxMonitor, initialize, open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.review.persistence.models import StorageError
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.retention import MaintenanceLog
from soc_agent.state.evidence import utc_now


def status(directory: Path):
    store = RuntimeStore(directory.resolve())
    state = store.state()
    pipeline = open_pipeline(directory.resolve(), store.config)
    audit = MaintenanceLog(directory.resolve() / "collection-audit.sqlite", pipeline)
    audit.entries()
    jobs = store.jobs()
    simulation = RuntimeResponseSimulation(store, pipeline)
    records = simulation.records()
    queue = pipeline.queue.counts()
    heartbeat_age = (utc_now() - datetime.fromisoformat(state["heartbeat"])).total_seconds()
    active = state["state"] == "RUNNING" and 0 <= heartbeat_age <= max(
        5, store.config.investigation_seconds + store.config.poll_seconds * 3
    )
    collection_good = state["collector"] in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY")
    ready = active and collection_good and state["llm"] == "AVAILABLE"
    if store.config.assessment_mode != "REAL_LLM":
        ready = active and collection_good and state["last_error"] is None
    ready = ready and not (
        jobs.get("BLOCKED", 0)
        or jobs.get("FAILED", 0)
        or state["circuit_open"]
        or state["last_error"]
        or any(r.status == "UNCERTAIN" for r in records)
    )
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
        "completed_scripted": jobs.get("DONE_SCRIPTED", 0),
        "blocked_investigations": jobs.get("BLOCKED", 0),
        "assessment_mode": store.config.assessment_mode,
        "real_llm_enabled": store.config.assessment_mode == "REAL_LLM",
        "response_execution": "DISABLED",
        "response_simulation": "RESPONSE_SIMULATION" if simulation.enabled() else "DISABLED",
        "automatic_human_approval": "DISABLED",
        "pending_response_reviews": sum(r.status == "PENDING_REVIEW" for r in records),
        "completed_simulations": sum(r.status == "SIMULATED" for r in records),
        "uncertain_simulations": sum(r.status == "UNCERTAIN" for r in records),
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
    init.add_argument(
        "--assessment-mode", choices=("SCRIPTED", "READ_ONLY", "REAL_LLM"), default="SCRIPTED"
    )
    init.add_argument("--env-file", type=Path)
    start = sub.add_parser("start")
    start.add_argument("--duration-seconds", type=float)
    start.add_argument(
        "--operator-uid", type=int, action="append", help="Opt-in same-UID Linux operator socket"
    )
    operator = sub.add_parser(
        "operator", help="Authenticated local request to the running monitor; no DB writes"
    )
    op = operator.add_subparsers(dest="operator_command", required=True)
    for command in ("pending", "audit", "feedback"):
        op.add_parser(command)
    for command in ("feedback-list", "candidates"):
        op.add_parser(command)
    experience = op.add_parser("experience")
    experience.add_argument("finding_id")
    submit = op.add_parser("feedback-submit")
    submit.add_argument("finding_id")
    submit.add_argument("--experience-id", required=True)
    submit.add_argument("--feedback-id", type=UUID, required=True)
    submit.add_argument(
        "--label", choices=("TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"), required=True
    )
    submit.add_argument(
        "--reason-code",
        choices=(
            "EXPECTED_ACTIVITY",
            "SUSPICIOUS_PATTERN",
            "INSUFFICIENT_CONTEXT",
            "INVESTIGATION_INACCURATE",
        ),
        required=True,
    )
    submit.add_argument("--supersedes", type=UUID)
    review = op.add_parser("candidate-review")
    review.add_argument("candidate_id")
    review.add_argument("--decision", choices=("APPROVE", "REJECT", "DEFER"), required=True)
    review.add_argument("--evaluation-id", required=True)
    offline = sub.add_parser(
        "learning-evaluate", help="Offline fixture trial; requires stopped monitor"
    )
    offline.add_argument("candidate_id")
    offline.add_argument("--repeated-failures", type=int, required=True)
    offline.add_argument("--multiple-accounts", type=int, required=True)
    for command in ("detail", "approve", "reject", "execute"):
        request = op.add_parser(command)
        request.add_argument("candidate_id")
        if command in ("approve", "reject", "execute"):
            request.add_argument("--expected-digest", required=True)
    sim = sub.add_parser("simulation", help="Opt-in pure simulator; only explicit test reviewers")
    simsub = sim.add_subparsers(dest="simulation_command", required=True)
    for command in ("enable", "disable", "list"):
        simsub.add_parser(command)
    request = simsub.add_parser("request")
    request.add_argument("finding_id")
    request.add_argument("--ttl-seconds", type=int, default=300)
    for command in ("approve", "reject", "execute"):
        review = simsub.add_parser(command)
        review.add_argument("candidate_id")
        if command != "execute":
            review.add_argument("--test-reviewer", required=True)
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
        elif args.command == "operator":
            from soc_agent.improvement_review.models import ReviewDecision
            from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackRequest
            from soc_agent.linux_runtime.operator import operator_request

            # Validate the original path before resolution can hide a symlink.
            directory = args.directory.absolute()
            feedback_request = (
                RuntimeFeedbackRequest(
                    feedback_id=args.feedback_id,
                    finding_id=args.finding_id,
                    expected_experience_id=args.experience_id,
                    label=args.label,
                    reason_code=args.reason_code,
                    supersedes=args.supersedes,
                )
                if args.operator_command == "feedback-submit"
                else None
            )

            reply = asyncio.run(
                operator_request(
                    directory,
                    args.operator_command,
                    candidate_id=getattr(args, "candidate_id", None),
                    expected_digest=getattr(args, "expected_digest", None),
                    finding_id=getattr(args, "finding_id", None),
                    feedback_request=feedback_request,
                    review_decision=ReviewDecision(args.decision)
                    if args.operator_command == "candidate-review"
                    else None,
                    expected_evaluation=getattr(args, "evaluation_id", None),
                )
            )
            print(json.dumps(reply))
            return 0 if reply["ok"] else 1
        elif args.command == "learning-evaluate":
            from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop

            with exclusive_runtime_lock(directory / "writer.lock"):
                result = RuntimeFeedbackLoop(LinuxMonitor(directory)).evaluate(
                    args.candidate_id,
                    repeated_failures=args.repeated_failures,
                    multiple_accounts=args.multiple_accounts,
                )
            print(json.dumps(result))
        elif args.command == "simulation":
            store = RuntimeStore(directory)
            if args.simulation_command == "list":
                simulation = RuntimeResponseSimulation(
                    store, open_pipeline(directory, store.config)
                )
                print(json.dumps([r.model_dump(mode="json") for r in simulation.records()]))
            else:
                # Local review/execution only while the monitor is stopped. Never race
                # the live writer or accept an LLM-issued approval/response instruction.
                with exclusive_runtime_lock(directory / "writer.lock"):
                    simulation = RuntimeResponseSimulation(
                        store, open_pipeline(directory, store.config)
                    )
                    command = args.simulation_command
                    if command in ("enable", "disable"):
                        simulation.set_enabled(command == "enable")
                        print(
                            json.dumps(
                                {
                                    "response_simulation": command,
                                    "actual_response_execution": "DISABLED",
                                }
                            )
                        )
                    else:
                        record = (
                            simulation.request(args.finding_id, ttl_seconds=args.ttl_seconds)
                            if command == "request"
                            else asyncio.run(simulation.execute(args.candidate_id))
                            if command == "execute"
                            else simulation.review(
                                args.candidate_id,
                                approve=command == "approve",
                                test_reviewer=args.test_reviewer,
                            )
                        )
                        print(record.model_dump_json())
        elif args.command == "stop":
            RuntimeStore(directory).request_stop()
            print(json.dumps({"stop_requested": True}))
        elif args.command == "start":
            if args.operator_uid is not None:
                from soc_agent.review.persistence.secure_storage import validate_directory

                validate_directory(args.directory.absolute())

            async def start_runtime():
                monitor = LinuxMonitor(directory)
                loop = asyncio.get_running_loop()
                for signum in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(signum, monitor.request_stop)
                try:
                    await monitor.run(
                        duration_seconds=args.duration_seconds,
                        operator_uids=tuple(args.operator_uid)
                        if args.operator_uid is not None
                        else None,
                    )
                finally:
                    for signum in (signal.SIGINT, signal.SIGTERM):
                        loop.remove_signal_handler(signum)

            asyncio.run(start_runtime())
            print(json.dumps(status(directory)))
        else:
            print(json.dumps(status(directory)))
    except (
        ValueError,
        OSError,
        RuntimeError,
        ExecutionError,
        ApprovalError,
        StorageError,
    ) as error:
        print(
            json.dumps(
                {"health": "FAILED", "readiness": "NOT_READY", "error": type(error).__name__}
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
