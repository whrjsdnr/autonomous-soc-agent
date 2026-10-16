"""Explicit live-research composition over the existing monitor, source queue and demo ledger."""

import asyncio
import sqlite3
import time
from pathlib import Path
from uuid import UUID, uuid4

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.queue import QueueFull
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory, validate_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.helper_transport import HelperCapture
from soc_agent.security_ai.operational.network_capture.live_session import (
    instructions,
    load_session,
    prepare,
    unprivileged,
)
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    PacketObservation,
)
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.live_input import LiveRequest, expected_source
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.service import ResearchDemo


class LiveResearch(ResearchDemo):
    attempt_limit = 256 * 1024
    capacity = 16  # Per bounded session, no automatic retry of unknown attempts.

    def __init__(self, directory, *, paths=None, timeout=30):
        super().__init__(directory, paths=paths, timeout=timeout)
        self.adapter = ResearchAdapter(
            self.directory, paths=paths, timeout=timeout, live_metadata=True
        )

    def snapshot(self):
        records, unknown = self._records()
        unknown = [key for key in unknown if key != self.active_key]
        return {
            "records": records,
            "unknown_attempts": unknown,
            "model_metrics": self._model_metrics(records, unknown),
            "worker_running": self.adapter.process is not None
            and self.adapter.process.returncode is None,
            "active_model": getattr(self, "active_model", None),
            "audit_integrity": "VERIFIED" if self.directory.exists() else "NO_DATA",
        }

    async def dispatch(self, request, key):
        expected_key = digest(
            {
                "session": str(request.capture_session),
                "flow": request.flow_id,
                "profile": request.profile,
            }
        )
        if key != expected_key:
            raise ValueError("LIVE_IDEMPOTENCY_KEY_MISMATCH")
        if request.origin == "NATIVE_AF_PACKET":
            if self.adapter.authorize_live is None:
                raise ValueError("LIVE_AUTHENTICATED_SOURCE_REQUIRED")
            await asyncio.to_thread(self.adapter.authorize_live, request)
        records, _ = self._records()
        old = next((r for r in records if r["key"] == key), None)
        if (
            old
            and old.get("receipt")
            and old["receipt"]["source_digest"] != expected_source(request)
        ):
            raise ValueError("LIVE_CACHED_SOURCE_MISMATCH")
        return await super().dispatch(request, key)


def bound_request(monitor: NetworkMonitor, session_id: UUID, event, flow, profile) -> LiveRequest:
    """Load durable packet/source references; never accepts an arbitrary feature vector."""
    monitor.store.verify_audit()
    if event.source.generation != str(session_id) or flow.close_reason not in {
        "IDLE_TIMEOUT",
        "ACTIVE_TIMEOUT",
    }:
        raise ValueError("LIVE_SESSION_OR_RESTART_GAP_MISMATCH")
    if monitor.config.idle_seconds != 30 or monitor.config.active_seconds != 120:
        raise ValueError("LIVE_FLOW_PRODUCER_TIMEOUT_MISMATCH")
    pipeline = monitor.pipeline
    packets, sources, identities = [], [], []
    with pipeline.queue.database.transaction(write=False) as c:
        for identity in flow.source_event_ids:
            row = c.execute(
                "SELECT * FROM realtime_events WHERE event_id=?", (identity,)
            ).fetchone()
            if row is None or row["status"] != "DONE":
                raise ValueError("LIVE_PACKET_NOT_COMMITTED")
            packet_event = pipeline.queue._decode(row)
            packet = pipeline.decode(packet_event)
            if not isinstance(packet, PacketObservation) or packet_event.source.generation != str(
                session_id
            ):
                raise ValueError("LIVE_PACKET_SESSION_MISMATCH")
            source = pipeline._source(packet_event, packet)
            pipeline.sources.load(source, expected_incident=pipeline.incident)
            packets.append(packet)
            sources.append(source)
            identities.append(UUID(identity))
    sources.append(pipeline._source(event, flow))
    receipt = build_receipt(pipeline.sources, incident_id=pipeline.incident, sources=tuple(sources))
    verify_receipt(receipt, pipeline.sources, incident_id=pipeline.incident, sources=tuple(sources))
    return LiveRequest(
        research_mode=True,
        profile=profile,
        invocation_id=uuid4(),
        origin="NATIVE_AF_PACKET" if monitor.config.origin == "NATIVE_AF_PACKET" else "FIXTURE",
        capture_session=session_id,
        flow_id=flow.flow_id,
        provenance_digest=receipt.receipt_digest,
        packets=tuple(packets),
        packet_event_ids=tuple(identities),
    )


class LiveMonitoring:
    """GUI-owned unprivileged companion; never launches the operator's privilege command."""

    def __init__(self, directory: Path, *, paths=None):
        self.root = directory / "live-network"
        self.paths = paths
        self.directory = None
        self.session = self.capture = self.monitor = self.demo = self.task = None
        self.handshake_task = None
        self.last_error = None
        self.state = "STOPPED"
        self.preparing = False
        self.start_cancelled = False
        self.profiles = ("quality", "edge")
        self.collection_done = asyncio.Event()
        self.pending = asyncio.Queue(
            maxsize=8
        )  # Only references; persistence is existing EventQueue.
        if self.root.exists():
            validate_directory(self.root)
            sessions = list(self.root.glob("session-*"))
            if len(sessions) > 8:
                raise ValueError("LIVE_SESSION_ARCHIVAL_REQUIRED")
            if sessions:
                self.directory = max(sessions, key=lambda p: p.stat().st_mtime_ns)
                try:
                    self.session = load_session(self.directory)
                    self.demo = LiveResearch(self.directory, paths=self.paths)
                    self.state = "RETAINED_SESSION_NOT_LIVE"
                except (OSError, ValueError, StorageError):
                    self.state = "UNKNOWN"
                    self.last_error = "RETAINED_LIVE_SESSION_IDENTITY_INVALID_NO_AUTO_RESUME"

    async def start(self, profiles=("quality", "edge"), *, seconds=60, max_packets=512):
        if self.preparing or (self.task is not None and not self.task.done()):
            raise ValueError("LIVE_SESSION_ALREADY_ACTIVE")
        self.preparing, self.start_cancelled = True, False
        self.state = "STARTING"
        try:
            return await self._start(profiles, seconds=seconds, max_packets=max_packets)
        except (OSError, ValueError, StorageError, sqlite3.Error):
            await self.stop()
            self.state = "ERROR"
            self.last_error = "LIVE_LISTENER_PREPARE_FAILED_STOP_AND_PREPARE_NEW_SESSION"
            return {"status": "ERROR", "listener_ready": False, "error": self.last_error}
        finally:
            self.preparing = False

    async def _start(self, profiles, *, seconds, max_packets):
        unprivileged()
        if self.task is not None and not self.task.done():
            raise ValueError("LIVE_SESSION_ALREADY_ACTIVE")
        if (
            not profiles
            or len(set(profiles)) != len(profiles)
            or any(p not in ("quality", "edge") for p in profiles)
        ):
            raise ValueError("LIVE_NETWORK_PROFILE_REQUIRED")
        create_private_directory(self.root)
        if len(list(self.root.glob("session-*"))) >= 8:
            raise ValueError("LIVE_SESSION_ARCHIVAL_REQUIRED")
        self.directory = self.root / ("session-" + uuid4().hex)
        self.session = prepare(self.directory, seconds=seconds, max_packets=max_packets)
        self.profiles, self.last_error = tuple(profiles), None
        self.monitor = None
        self.pending = asyncio.Queue(maxsize=8)
        self.collection_done = asyncio.Event()
        self.demo = LiveResearch(self.directory, paths=self.paths)
        # Environment verification is READ-only. No socket/capture/model inference yet.
        ready = await self.demo.start()
        if self.start_cancelled:
            self.state = "STOPPED"
            return {"status": "STOPPED", "error": "LIVE_START_CANCELLED_NO_CAPTURE"}
        if ready.get("status") == "BLOCKED":
            self.state = "BLOCKED"
            return ready
        runtime = self.directory / "runtime"
        initialize(
            runtime, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
        )
        configure(runtime, CaptureConfig(interface="lo"))
        self.capture = HelperCapture(self.directory, self.session)
        self.demo.adapter.authorize_live = self.validate_native_source
        self.state = "AUTHENTICATION_REQUIRED"
        self.task = asyncio.create_task(self._run())
        return self.helper_command(str(self.session.session_id))

    def helper_command(self, session_id):
        """Only expose a command while this backend owns its accepting listener."""
        if (
            self.session is None
            or str(self.session.session_id) != session_id
            or self.state != "AUTHENTICATION_REQUIRED"
            or self.capture is None
            or not self.capture.listener_ready()
            or self.task is None
            or self.task.done()
        ):
            return {
                "status": "BLOCKED",
                "listener_ready": False,
                "error": "PREPARE_NEW_LIVE_SESSION",
            }
        return {**instructions(self.directory, self.session), "listener_ready": True}

    def validate_native_source(self, request):
        if (
            self.capture is None
            or self.capture.ready is None
            or self.capture.counter_issue is not None
            or self.capture.reader_failed()
            or (self.capture.closed.is_set() and self.capture.terminal is None)
            or self.monitor is None
            or self.start_cancelled
            or self.last_error is not None
            or self.monitor.metrics.get("finalization") != "VERIFIED"
            or not self.capture.completion_verified()
            or request.capture_session != self.session.session_id
            or self.monitor.metrics["last_error"]
        ):
            raise ValueError("LIVE_AUTHENTICATED_SOURCE_REQUIRED")
        pipeline = self.monitor.pipeline
        with pipeline.queue.database.transaction(write=False) as c:
            rows = c.execute(
                "SELECT * FROM realtime_events WHERE status='DONE' "
                "AND json_extract(payload,'$.metadata.code')='flow'"
            ).fetchall()
        # Do not retain an outer SQLite read lock across nested provenance reads.
        for row in rows:
            event = pipeline.queue._decode(row)
            flow = pipeline.decode(event)
            if flow.flow_id == request.flow_id:
                expected = bound_request(
                    self.monitor, self.session.session_id, event, flow, request.profile
                )
                if expected.model_dump(exclude={"invocation_id"}) != request.model_dump(
                    exclude={"invocation_id"}
                ):
                    raise ValueError("LIVE_DURABLE_SOURCE_MISMATCH")
                return
        raise ValueError("LIVE_DURABLE_FLOW_MISSING")

    def on_flow(self, event, flow, receipt):
        # Native packet-budget/shutdown/restart slices differ from the training
        # flow window. Keep them diagnostic, never pad or infer a complete flow.
        if flow.close_reason not in {"IDLE_TIMEOUT", "ACTIVE_TIMEOUT"}:
            return
        if self.pending.full():
            raise QueueFull("LIVE_INFERENCE_BACKPRESSURE")
        self.pending.put_nowait((event, flow))

    async def _consume(self):
        failures = 0
        while True:
            if self.collection_done.is_set() and self.pending.empty():
                return
            try:
                item = await asyncio.wait_for(self.pending.get(), 0.2)
            except TimeoutError:
                continue
            event, flow = item
            for profile in self.profiles:
                if failures >= 2:
                    self.last_error = "LIVE_CIRCUIT_OPEN_NO_AUTOMATIC_RETRY"
                    return
                request = bound_request(self.monitor, self.session.session_id, event, flow, profile)
                outcome = await self.demo.dispatch(
                    request,
                    digest(
                        {
                            "session": str(self.session.session_id),
                            "flow": flow.flow_id,
                            "profile": profile,
                        }
                    ),
                )
                failures += outcome["status"] == "UNKNOWN"

    async def _run(self):
        consumer = None
        try:
            # Own and join the thread-backed accept, even when the parent is cancelled.
            self.handshake_task = asyncio.create_task(asyncio.to_thread(self.capture.handshake))
            await asyncio.shield(self.handshake_task)
            # Start reading before synchronous Runtime/SQLite initialization.
            self.capture.start_reader()
            self.state = "LIVE_COLLECTION"
            runtime = self.directory / "runtime"
            with exclusive_runtime_lock(runtime / "writer.lock"):
                store = RuntimeStore(runtime)
                store.event(
                    "LIVE_HELPER_VERIFIED",
                    {
                        "session_digest": digest(self.session.model_dump(mode="json")),
                        "ready_digest": digest(self.capture.ready.model_dump(mode="json")),
                    },
                )
                self.monitor = NetworkMonitor(
                    runtime,
                    store,
                    capture=self.capture,
                    flow_handler=self.on_flow,
                    generation=str(self.session.session_id),
                )
                self.capture.stop = self.monitor.stopped
                await self.monitor.run()
                store.event(
                    "LIVE_HELPER_CLOSED",
                    {
                        "terminal_digest": digest(self.capture.terminal.model_dump(mode="json"))
                        if self.capture.terminal
                        else "UNKNOWN",
                    },
                )
            if self.monitor.metrics["last_error"]:
                raise ValueError("LIVE_CAPTURE_GAP_OR_MONITOR_ERROR")
            if self.start_cancelled or self.monitor.metrics.get("finalization") != "VERIFIED":
                raise ValueError("LIVE_FINALIZATION_REQUIRED_NO_INFERENCE")
            self.state = "COLLECTION_STOPPED_RESEARCH_DRAINING"
            self.collection_done.set()
            consumer = asyncio.create_task(self._consume())
            await asyncio.wait_for(consumer, 90)
            self.state = "STOPPED"
        except asyncio.CancelledError:
            self.state = "STOPPED"
            raise
        except (OSError, ValueError, TimeoutError, StorageError, sqlite3.Error) as error:
            self.last_error = (
                "LIVE_HELPER_HANDSHAKE_FAILED_STOP_AND_PREPARE_NEW_SESSION"
                if self.capture.ready is None
                else "LIVE_SESSION_FAILED_OR_BUDGET_EXHAUSTED_NO_RETRY"
            )
            if str(error) == "HELPER_LISTENER_CLOSED" or (
                self.capture.channel is None and self.capture.listener.fileno() == -1
            ):
                if self.capture.ready is None:
                    self.last_error = "LIVE_LISTENER_CLOSED_STOP_AND_PREPARE_NEW_SESSION"
            if self.capture.counter_issue:
                self.last_error = self.capture.counter_issue["error"]
                if self.capture.counter_issue.get("helper_error") == "HELPER_TRANSPORT_TIMEOUT":
                    self.last_error = "HELPER_TRANSPORT_TIMEOUT_COUNTER_INTEGRITY_FAILED"
            elif self.capture.reader_error:
                self.last_error = self.capture.reader_error
            self.state = "ERROR"
        finally:
            try:
                self.capture.close()
            finally:
                if self.handshake_task is not None:
                    await asyncio.gather(self.handshake_task, return_exceptions=True)
                await self.demo.stop()
                if consumer is not None and not consumer.done():
                    consumer.cancel()
                    await asyncio.gather(consumer, return_exceptions=True)

    async def stop(self):
        self.start_cancelled = True
        self.collection_done.set()
        try:
            if self.capture is not None:
                self.capture.close()
        finally:
            if self.monitor is not None:
                self.monitor.stopped.set()
            if self.demo is not None:
                await self.demo.stop()
            if self.task is not None and not self.task.done():
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
        self.state = "STOPPED"
        return await asyncio.to_thread(self.snapshot)

    def snapshot(self):
        try:
            listener_ready = bool(
                self.capture is not None
                and self.capture.listener_ready()
                and self.task is not None
                and not self.task.done()
                and self.state == "AUTHENTICATION_REQUIRED"
            )
            state = self.state
            last_error = self.last_error or (self.capture.reader_error if self.capture else None)
            if self.capture is not None and self.capture.reader_failed():
                state = "ERROR"
                last_error = last_error or self.capture.reader_error
            if state == "AUTHENTICATION_REQUIRED" and not listener_ready:
                if (
                    self.capture is not None
                    and self.capture.channel is not None
                    and not self.capture.closed.is_set()
                ):
                    state = "HELPER_VALIDATING"
                else:
                    state = "ERROR"
                    last_error = "LIVE_LISTENER_CLOSED_STOP_AND_PREPARE_NEW_SESSION"
            if (
                state == "LIVE_COLLECTION"
                and self.capture is not None
                and self.capture.terminal is not None
            ):
                state = "COLLECTION_STOPPED_RESEARCH_DRAINING"
            live = bool(
                self.capture is not None
                and self.capture.is_live()
                and self.capture.last_heartbeat
                and time.monotonic() - self.capture.last_heartbeat <= 2
                and self.task is not None
                and not self.task.done()
            )
            research = (
                self.demo.snapshot()
                if self.demo
                else {
                    "records": [],
                    "worker_running": False,
                    "model_metrics": {},
                    "audit_integrity": "NO_DATA",
                }
            )
            network = (
                RuntimeStore(self.directory / "runtime").state().get("network", {})
                if (self.directory and (self.directory / "runtime/monitor.sqlite").is_file())
                else {}
            )
            return {
                "state": "LIVE_RESEARCH_INFERENCE"
                if live and research["worker_running"]
                else "LIVE_COLLECTION"
                if live
                else state
                if state != "LIVE_COLLECTION"
                else "UNKNOWN",
                "listener_ready": listener_ready,
                "listener_address": "@soc-live-" + str(self.session.session_id)
                if listener_ready
                else None,
                "prepare_active": self.preparing or bool(self.task and not self.task.done()),
                "collection_live": live,
                "capture_permission": "VERIFIED_DROPPED_CAP_NET_RAW"
                if live
                else "USER_AUTHENTICATION_REQUIRED"
                if listener_ready
                else "NO_ACTIVE_HELPER",
                "session_id": str(self.session.session_id) if self.session else None,
                "input_origin": "NATIVE_AF_PACKET" if self.session else "NO_DATA",
                "parity": "METADATA_REFERENCE_CHECKED_IN_WORKER_PHYSICAL_VALIDATION_PENDING",
                "network": {
                    **network,
                    **(
                        {k: None for k in ("packets_per_second", "flows_per_minute")}
                        if not live
                        else {}
                    ),
                },
                "research": research,
                "last_error": last_error or network.get("last_error"),
                "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
                "operational_input": "NOT_INFERABLE",
                "write_policy": "WRITE_DENIED",
            }
        except (OSError, ValueError, StorageError, sqlite3.Error):
            return {
                "state": "UNKNOWN",
                "collection_live": False,
                "last_error": "LIVE_STORAGE_OR_AUDIT_INVALID",
                "research": {},
                "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
                "write_policy": "WRITE_DENIED",
            }
