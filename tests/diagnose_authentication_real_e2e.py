"""Privacy-preserving native collection and real governed READ tool diagnostic, no LLM."""

import argparse
import asyncio
import json
from pathlib import Path
from uuid import UUID

from soc_agent.realtime.queue import EventQueue
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import (
    AuthenticationReadQuery,
    AuthenticationReadView,
    authentication_read_registry,
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    LinuxAuthenticationCollector,
    ingest_authentication,
)
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--incident", type=UUID, required=True)
    parser.add_argument("--limit", type=int, default=16)
    parser.add_argument("--include-pam-failures", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if (
        not args.directory.is_absolute()
        or (args.directory.exists() and not args.resume)
        or not 1 <= args.limit <= 128
    ):
        parser.error("New absolute isolated directory and bounded limit required")
    if args.resume and not args.directory.is_dir():
        parser.error("Resume directory missing")
    if not args.resume:
        create_private_directory(args.directory, exist_ok=False)
    lock = args.directory / "diagnostic.lock"
    if not lock.exists():
        create_private_file(lock)
    with exclusive_runtime_lock(lock):
        queue = (
            EventQueue(args.directory / "queue.sqlite")
            if args.resume
            else EventQueue.create(args.directory / "queue.sqlite")
        )
        options = {"allowed_lateness_seconds": 60, "max_future_skew_seconds": 5}
        store = (
            OperationalSourceStore(args.directory / "sources.sqlite", **options)
            if args.resume
            else OperationalSourceStore.create(args.directory / "sources.sqlite", **options)
        )
        collector = LinuxAuthenticationCollector(include_pam_failures=args.include_pam_failures)
        AuthenticationPipeline(queue, store, args.incident, collector_identity=collector.identity)
        events = collector.poll(queue.cursor(collector.identity), limit=args.limit)
        for event in events:
            queue.enqueue(event, cursor_source=collector.identity)
        # A second native read exercises dedup without moving the retained cursor backward.
        repeated = LinuxAuthenticationCollector(
            include_pam_failures=args.include_pam_failures
        ).poll(limit=1)
        dedup = bool(repeated) and not queue.enqueue(repeated[0])
        abandoned = queue.claim()  # simulate stopped worker before acknowledgement
        reopened_queue = EventQueue(queue.database.path)
        with reopened_queue.database.transaction(write=False) as c:
            retained_claim = c.execute(
                "SELECT status,token FROM realtime_events WHERE event_id=?",
                (str(abandoned.event.event_id) if abandoned else "",),
            ).fetchone()
        restored_claim = bool(
            abandoned
            and retained_claim
            and retained_claim["status"] == "CLAIMED"
            and retained_claim["token"] == abandoned.token
        )
        reopened = AuthenticationPipeline(
            reopened_queue,
            OperationalSourceStore(store.database.path, **options),
            args.incident,
            collector_identity=collector.identity,
        )
        reopened.queue.recover()  # sole writer lock held
        mapped_replay = False
        # Process preceding unsupported records, then stop a worker after the REAL
        # mapped source transaction commits but before its queue acknowledgement.
        for _ in range(reopened.queue.capacity * reopened.queue.retry_limit):
            with reopened.queue.database.transaction(write=False) as c:
                row = c.execute(
                    "SELECT * FROM realtime_events WHERE status='PENDING' ORDER BY rowid LIMIT 1"
                ).fetchone()
                event = reopened.queue._decode(row) if row else None
            if event is None:
                break
            if dict(event.normalized_fields).get("parse_status") == "MAPPED_AUTHENTICATION":
                stopped = reopened.queue.claim()
                ingest_authentication(
                    stopped.event,
                    expected_event_digest=stopped.event.source_digest,
                    store=reopened.store,
                    incident_id=args.incident,
                )
                restarted = AuthenticationPipeline(
                    EventQueue(queue.database.path),
                    OperationalSourceStore(store.database.path, **options),
                    args.incident,
                    collector_identity=collector.identity,
                )
                restarted.queue.recover()
                replay = restarted.step()
                mapped_replay = not isinstance(replay, str) and replay.admission.duplicate
                reopened = restarted
                break
            reopened.step()
        for _ in range(reopened.queue.capacity * reopened.queue.retry_limit):
            if reopened.step() == "IDLE":
                break
        else:
            raise ValueError("AUTH_DIAGNOSTIC_DRAIN_LIMIT")
        # Restarted collector validates exact retained cursor content and collects next batch.
        extra = LinuxAuthenticationCollector(include_pam_failures=args.include_pam_failures).poll(
            reopened.queue.cursor(collector.identity), limit=1
        )
        for event in extra:
            reopened.queue.enqueue(event, cursor_source=collector.identity)
        for _ in range(reopened.queue.capacity * reopened.queue.retry_limit):
            if reopened.step() == "IDLE":
                break
        else:
            raise ValueError("AUTH_DIAGNOSTIC_DRAIN_LIMIT")
        auth_duplicate = False
        repeated_auth = LinuxAuthenticationCollector(
            include_pam_failures=args.include_pam_failures
        ).poll(limit=128)
        matched = next(
            (
                e
                for e in repeated_auth
                if dict(e.normalized_fields).get("parse_status") == "MAPPED_AUTHENTICATION"
            ),
            None,
        )
        if matched is not None and not reopened.queue.enqueue(matched):
            duplicate_receipt = ingest_authentication(
                matched,
                expected_event_digest=matched.source_digest,
                store=reopened.store,
                incident_id=args.incident,
            )
            auth_duplicate = duplicate_receipt is not None and duplicate_receipt.admission.duplicate
        view = read_authentication_view(reopened)
        final_reopen = AuthenticationPipeline(
            EventQueue(queue.database.path),
            OperationalSourceStore(store.database.path, **options),
            args.incident,
            collector_identity=collector.identity,
        )
        window_restored = read_authentication_view(final_reopen) == view
        investigation = await investigate_authentication(final_reopen)
        completed = investigation.plan.steps[0].status.value == "completed"
        from soc_agent.execution.errors import ExecutionDeniedError
        from soc_agent.tools import Tool, ToolMetadata

        registry = authentication_read_registry(reopened)
        write_calls = []

        async def write_spy(value):
            write_calls.append(value)
            raise AssertionError("WRITE spy invoked")

        guarded_write = Tool(
            ToolMetadata(
                name="disable_account",
                description="inert spy",
                permission="system_write",
                risk_level="high",
            ),
            AuthenticationReadQuery,
            AuthenticationReadView,
            write_spy,
            registry.execution_guard,
        )
        denied = False
        try:
            await guarded_write.execute({"incident_id": str(args.incident)})
        except ExecutionDeniedError:
            denied = True
        if write_calls or not denied:
            raise ValueError("READ_ONLY_BOUNDARY_FAILURE")
        # Do not emit raw evidence/state/source identities. Only counts and hashes.
        summary = {
            "native_records_collected": len(events) + len(extra),
            "queue_records_persisted": view.queue_records_persisted,
            "authentication_events_verified": view.authentication_events_verified,
            "authentication_events_rejected": view.authentication_events_rejected,
            "authentication_events_unsupported": view.authentication_events_unsupported,
            "authentication_windows": len(view.authentication_window),
            "provenance_receipts": len(view.provenance_reference),
            "native_duplicate_recapture_deduplicated": dedup,
            "worker_claim_restored": restored_claim,
            "mapped_auth_after_source_commit_replayed_duplicate": mapped_replay,
            "source_window_provenance_restored": window_restored,
            "authentication_recapture_deduplicated": auth_duplicate,
            "write_request_denied": denied,
            "write_spy_calls": len(write_calls),
            "collector_cursor_validated_after_reopen": True,
            "agent_read_tool_completed": completed,
            "llm_executed": False,
            "agent_evidence_digest": view.evidence_digest,
            "inference_status": view.inference_status,
            "action_policy": view.action_policy,
            "status": "INCONCLUSIVE",
        }
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
