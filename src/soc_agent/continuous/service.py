"""Independent collector task, durable bounded handoff and isolated analysis process.

This ordinary-user service never starts a privileged helper. Native installation
and sustained TCX authority are distinct administrator-governed service contracts.
"""

import asyncio
import json
import os
import resource
import time
from collections.abc import Callable
from pathlib import Path
from typing import ParamSpec, TypeVar
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from soc_agent.continuous.models import require_source_authority
from soc_agent.continuous.source import ReplaySource
from soc_agent.continuous.store import Store
from soc_agent.gui.analysis_service import AnalysisService
from soc_agent.realtime.queue import QueueFull
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.operational.network_capture.streaming_flow import StreamingFlows
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import JOB, PacketWindowJob

P = ParamSpec("P")
T = TypeVar("T")


class ContinuousRuntime:
    def __init__(
        self,
        directory: Path,
        *,
        source=None,
        analysis=None,
        journal_transport=None,
        dns_source=None,
    ):
        self.directory = directory
        self.store = Store(directory)
        self.store.require_streaming_schema()
        self.config = self.store.config
        from soc_agent.continuous.authentication import AuthenticationWindows
        from soc_agent.continuous.tcx_producer import TCXProducer

        self.source = source or (
            TCXProducer(self.config)
            if self.config.source == "NATIVE_SERVICE"
            else ReplaySource(self.config)
        )
        self.auth = AuthenticationWindows(self.config.authentication_packages)
        self.journal = journal_transport
        self.dns_source = dns_source
        self.dns_session = getattr(dns_source, "session", None)
        if self.config.dns_session and self.dns_source is None:
            from soc_agent.continuous.dns_source import inspect

            # Metadata validation is read-only. Allocate the listener only inside
            # run's authorized, locked cleanup scope, never during construction.
            self.dns_session = inspect(
                self.config.dns_session,
                namespace=self.config.namespace,
                sha256=self.config.dns_session_sha256,
            )
        if self.config.journal_replay_file:
            from soc_agent.continuous.journal_transport import JournalTransport, StoredJournalReader

            self.journal = JournalTransport(
                directory / "authentication",
                StoredJournalReader(
                    self.config.journal_replay_file, self.config.journal_replay_sha256
                ),
            )
        self.journal_state = "NOT_ATTACHED"
        self.auth_source_sha = (
            digest(self.journal.reader.identity) if self.journal else self.config.input_sha256
        )
        from soc_agent.continuous.native_windows import NativeWindows

        self.native_windows = NativeWindows(
            self.config.namespace, str(self.store.database.store_id)
        )
        from soc_agent.continuous.capture import CaptureWindows

        self.capture_windows = CaptureWindows(
            self.config.namespace, self.config.input_sha256, self.config.profiles
        )
        self.analysis = analysis or AnalysisService(
            directory / "analysis", self.config.ml_root, defer_investigation=True
        )
        self.investigations = None
        self.investigation_progress = {"state": "NOT_STARTED", "provider": "SCRIPTED"}
        self.investigation_snapshot = {}
        self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
        self.epoch = uuid5(
            NAMESPACE_URL, str(self.store.database.store_id) + self.config.input_sha256
        )
        self.last_sequence = 0
        self.last_event_ns = None
        self.done = asyncio.Event()
        self.stop = asyncio.Event()
        self.collector_state = "STOPPED"
        self.worker_state = "STOPPED"
        self.last_error = None
        self.stop_reason = None
        self.collector_failure = None
        self.circuit = False
        self.worker_failures = 0
        self.approval_wait_cancelled = False
        self.collector_failures = 0
        self.metrics = {
            k: 0
            for k in [
                "received",
                "packets",
                "native_events",
                "auth_windows",
                "recovered_events",
                "dns_inputs",
                "dns_metadata_bytes",
                "dns_rejected",
                "authentication_inputs",
                "duplicates",
                "excluded",
                "source_gaps",
                "invalid",
                "flows",
                "eligible",
                "incomplete",
                "queue_dropped",
                "predictions",
                "incidents",
                "model_errors",
                "collector_restarts",
            ]
        }
        self.last_results = []
        self.output = None
        from soc_agent.security_ai.research.isolated_dns import IsolatedDNS

        self.dns = IsolatedDNS(
            self.dns_session.session_id if self.dns_session else self.epoch,
            max_observations=77312 if self.dns_session else 38656,
        )
        self.dns_window = None
        self.dns_sequence = 0
        self.started = time.monotonic()
        self.collector_event_unix = None
        self.worker_observed_unix = None
        self.storage_lock = asyncio.Lock()
        self.storage_health = dict(pending=False, last_seconds=None, max_seconds=0.0)

    def snapshot(self):
        analysis = self.analysis.snapshot()
        authentication = {"state": "NOT_ATTACHED", "events": None}
        if self.config.authentication_runtime:
            from soc_agent.linux_runtime.operator import status

            authentication = status(self.config.authentication_runtime)
        return dict(
            orchestration=self.investigation_snapshot
            | dict(worker=dict(self.investigation_progress)),
            authentication=authentication,
            mode="CONTINUOUS",
            source=self.config.source,
            state="DEGRADED"
            if self.circuit
            or self.collector_state == "CIRCUIT_OPEN"
            or getattr(self.source, "failure", None)
            else "RUNNING",
            service_pid=os.getpid(),
            collector=(
                self.source.state
                if self.config.source == "NATIVE_SERVICE"
                else self.collector_state
            ),
            worker=self.worker_state,
            collection_live=(
                self.config.source == "NATIVE_SERVICE"
                and not getattr(self.source, "failure", None)
                and self.metrics["native_events"] > 0
                and self.source.state in ("RUNNING", "DEGRADED")
            ),
            source_assurance=(
                "ROOT_INSTALLED_PASSIVE_TCX"
                if self.config.source == "NATIVE_SERVICE"
                else "REPLAY_ONLY_NO_NATIVE_CAPTURE"
            ),
            native_model="EXACT_RETAINED_WINDOW_ACTION_APPROVAL_REQUIRED",
            capture_window=dict(
                id=self.capture_windows.last_window,
                assessment=self.capture_windows.last_capture,
                pending_events=len(self.capture_windows.events),
                abandoned_partial=self.capture_windows.abandoned,
            ),
            producer=getattr(self.source, "snapshot", {})
            | (
                dict(
                    receiver_queue_depth=getattr(self.source, "receiver_queue_depth", 0),
                    receiver_dropped_batches=getattr(self.source, "receiver_dropped_batches", 0),
                    last_message_monotonic=getattr(self.source, "last_message_monotonic", None),
                    last_validated_monotonic=getattr(self.source, "last_validated_monotonic", None),
                    last_data_monotonic=getattr(self.source, "last_data_monotonic", None),
                    last_root_clock=getattr(self.source, "last_root_clock", None),
                    failure=getattr(self.source, "failure", None),
                )
                if self.config.source == "NATIVE_SERVICE"
                else {}
            ),
            collector_cleanup=(
                getattr(self.source, "remote_cleanup", "UNKNOWN")
                if self.config.source == "NATIVE_SERVICE"
                else "NOT_APPLICABLE_REPLAY"
            ),
            collector_failure=self.collector_failure,
            auth_pending=len(self.auth.records),
            authentication_transport=dict(
                state=self.journal_state,
                source=self.journal.reader.identity if self.journal else None,
            ),
            heartbeat_unix=time.time(),
            component_health=dict(
                collector_event_unix=self.collector_event_unix,
                collector_message_unix=getattr(self.source, "last_message_unix", None),
                worker_observed_unix=self.worker_observed_unix,
                worker_child_running=analysis.get("worker_running", False),
                worker_child_returncode=analysis.get("child_returncode"),
                worker_heartbeat_scope="SUPERVISOR_OBSERVATION_NOT_MODEL_PROGRESS",
                collector_heartbeat_scope="AUTHENTICATED_ROOT_MESSAGE"
                if self.config.source == "NATIVE_SERVICE"
                else "REPLAY_EVENT_NOT_LIVE_CAPTURE",
                automatic_kernel_restart=False,
                storage=dict(self.storage_health),
            ),
            uptime_seconds=time.monotonic() - self.started,
            clock_epoch=str(self.epoch),
            metrics=dict(self.metrics),
            queue=self.store.queue.counts(),
            circuit_open=self.circuit,
            # DNS cleanup may still be draining after the first source failure.
            # Observers must see that failure before a later Collector STOP.
            last_error=self.last_error
            or (getattr(self.source, "failure", None) or {}).get("code")
            or getattr(self.dns_source, "last_error", None),
            stop_reason=self.stop_reason,
            analysis=analysis,
            recent_results=list(self.last_results),
            dns=self.dns.snapshot(),
            dns_transport=(
                self.dns_source.snapshot
                if self.dns_source
                else dict(
                    state="WAITING_APPROVED_START"
                    if self.dns_session
                    else "NOT_COLLECTED_IN_THIS_SCOPE",
                    origin="NO_DATA",
                )
            ),
            dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
            api="NOT_AUTOMATICALLY_AUTHORIZED",
            audit="VERIFIED",
            resources=dict(
                cpu_seconds=time.process_time(),
                peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            ),
            cleanup="PENDING_SERVICE_STOP",
        )

    async def storage(self, operation: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """Keep Native fsync/SQLite work off the authenticated receiver's event loop.

        Serialize writes and join them before declaring cancellation/cleanup. The
        durable operation and all of its validation remain unchanged.
        """
        if self.config.source != "NATIVE_SERVICE":
            return operation(*args, **kwargs)
        async with self.storage_lock:
            started = time.monotonic()
            self.storage_health.update(
                pending=True, operation=getattr(operation, "__name__", type(operation).__name__)
            )
            pending = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
            try:
                return await asyncio.shield(pending)
            except asyncio.CancelledError:
                await pending
                raise
            finally:
                elapsed = time.monotonic() - started
                self.storage_health.update(
                    pending=False,
                    last_seconds=elapsed,
                    max_seconds=max(elapsed, self.storage_health["max_seconds"]),
                )

    async def publish(self):
        await self.storage(self.store.update, self.snapshot())

    async def handoff(self, job):
        self.metrics["flows"] += int(job.kind == "packet_window")
        existing = self.directory / "inputs" / (digest(job.model_dump(mode="json")) + ".json")
        if (
            not existing.exists()
            and len(list((self.directory / "inputs").glob("*.json"))) >= self.config.max_windows
        ):
            raise ValueError("CONTINUOUS_WINDOW_RETENTION_REQUIRES_ARCHIVAL")
        if job.kind == "packet_window":
            self.metrics["eligible" if job.quality == "ELIGIBLE" else "incomplete"] += 1
        elif job.kind == "tcx_analysis":
            from soc_agent.security_ai.tcx_input import candidates

            # Count independently validated vectors, not the sealed job envelope.
            # This is a display metric, never an inference or approval grant.
            rows = candidates(job)[2]
            self.metrics["flows"] += len(rows)
            self.metrics["eligible"] += sum(row["eligible"] for row in rows)
            self.metrics["incomplete"] += sum(not row["eligible"] for row in rows)
        try:
            await self.storage(self.store.enqueue, job)
        except QueueFull:
            self.metrics["queue_dropped"] += 1
            await self.storage(
                self.store.event,
                "CONTINUOUS_INFERENCE_QUEUE_FULL",
                dict(
                    job_digest=digest(job.model_dump(mode="json")),
                    count=self.metrics["queue_dropped"],
                ),
            )

    async def complete(self, items, witness):
        for item in items:
            quality = (
                "ELIGIBLE"
                if item.flow.close_reason in ("IDLE_TIMEOUT", "ACTIVE_TIMEOUT")
                else "INCOMPLETE"
            )
            job = PacketWindowJob(
                kind="packet_window",
                origin="OFFLINE_PCAP" if self.config.source == "PCAP_REPLAY" else "FIXTURE",
                session=self.epoch,
                source_sha256=self.config.input_sha256,
                clock_epoch=str(self.epoch),
                quality=quality,
                close_reason=item.flow.close_reason,
                packets=item.packets,
                identities=item.identities,
                witness_ns=witness,
                profiles=self.config.profiles,
            )
            await self.handoff(job)

    async def observe(self, raw, *, recovering=False):
        if (
            not isinstance(raw, dict)
            or type(raw.get("sequence")) is not int
            or raw["sequence"] != self.last_sequence + 1
        ):
            self.metrics["source_gaps"] += 1
            await self.complete(self.aggregator.close("RESTART_GAP"), self.last_event_ns or 0)
            self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
            raise ValueError("CONTINUOUS_SOURCE_SEQUENCE_GAP")
        if not recovering:
            await self.storage(self.store.retain, raw)
        self.last_sequence = raw["sequence"]
        self.metrics["received"] += 1
        identity = str(UUID(raw["id"]))
        kind = raw.get("kind")
        if kind not in (
            "packet",
            "job",
            "excluded",
            "authentication",
            "auth_watermark",
            "native_tcx",
            "native_seal",
        ):
            raise ValueError("CONTINUOUS_SOURCE_RECORD_KIND")
        if kind == "packet":
            checked = PacketObservation.model_validate(raw["packet"])
            if checked.timestamp_origin != "FIXTURE":
                raise ValueError("CONTINUOUS_REPLAY_CANNOT_ATTEST_NATIVE")
        if kind == "job" and JOB.validate_python(raw["job"]).kind not in (
            "raw_dns",
            "stored_dns",
            "stored_records",
            "collector_error",
        ):
            raise ValueError("CONTINUOUS_SOURCE_JOB_DOMAIN_NOT_ALLOWED")
        already_seen = False
        if kind not in ("native_tcx", "native_seal"):
            already_seen = self.store.seen(
                identity, {key: value for key, value in raw.items() if key != "sequence"}
            )
        if already_seen and not recovering:
            self.metrics["duplicates"] += 1
            return
        if kind in ("native_tcx", "native_seal"):
            if self.config.source != "NATIVE_SERVICE":
                raise ValueError("CONTINUOUS_REPLAY_CANNOT_ATTEST_NATIVE")
            # Commit the exact authenticated Root transcript before window application.
            # Restart replays it through the same decoder; no partial window becomes sealed.
            key = "native-window:" + raw["id"]
            if await self.storage(self.store.retain_auxiliary, key, raw):
                jobs, capture = self.capture_windows.accept(raw)
                if capture is not None:
                    await self.storage(
                        self.store.event, "CONTINUOUS_CAPTURE_WINDOW_REASSESSED", capture
                    )
                for job in jobs:
                    await self.handoff(job)
            self.metrics["native_events"] += int(kind == "native_tcx")
            self.metrics["packets"] += int(kind == "native_tcx")
            await self.storage(self.store.applied, raw["sequence"])
            return
        if kind in ("authentication", "auth_watermark"):
            from soc_agent.continuous.authentication import normalized

            if self.journal is not None:
                raise ValueError("CONTINUOUS_AUTH_SOURCE_MULTIPLEX_CONFLICT")
            if not self.config.authentication_packages:
                raise ValueError("CONTINUOUS_AUTH_MODEL_PACKAGE_REQUIRED")
            if kind == "authentication":
                cursor, record = normalized(raw["authentication"], self.config.input_sha256)
                jobs = self.auth.observe(record, source_digest=self.config.input_sha256)
                self.metrics["authentication_inputs"] += 1
                self.store.event(
                    "CONTINUOUS_AUTH_CURSOR_RETAINED",
                    dict(cursor_digest=digest(cursor), event=str(record.record_id)),
                )
            else:
                from datetime import datetime

                watermark = datetime.fromisoformat(raw["watermark"])
                if watermark.tzinfo is None:
                    raise ValueError("CONTINUOUS_AUTH_WATERMARK_TIMEZONE")
                jobs = self.auth.advance(watermark, source_digest=self.config.input_sha256)
            for job in jobs:
                self.metrics["auth_windows"] += 1
                await self.handoff(job)
            self.store.applied(raw["sequence"])
            return
        if kind == "packet":
            packet = PacketObservation.model_validate(raw["packet"])
            if packet.timestamp_origin != "FIXTURE":
                raise ValueError("CONTINUOUS_REPLAY_CANNOT_ATTEST_NATIVE")
            if "tcx_wire_hex" in raw:
                from soc_agent.continuous.tcx_producer import decode, replay_packet

                event = decode(
                    bytes.fromhex(raw["tcx_wire_hex"]),
                    namespace=self.config.namespace,
                    session=self.epoch,
                    program=self.config.input_sha256,
                    sequence=raw["sequence"],
                    clock="FIXTURE_PCAP_EVENT_NS",
                )
                projected = replay_packet(event, packet.interface_id)
                if any(
                    getattr(projected, k) != getattr(packet, k)
                    for k in (
                        "source_address",
                        "destination_address",
                        "source_port",
                        "destination_port",
                        "ip_length",
                        "frame_length",
                        "tcp_flags",
                        "timestamp",
                    )
                ):
                    raise ValueError("CONTINUOUS_TCX_REPLAY_PARITY")
            self.metrics["packets"] += 1
            if packet.dns:
                self.metrics["dns_inputs"] += 1
            ns = timestamp_ns(packet)
            window = ns // (self.config.metadata_window_seconds * 10**9)
            if self.dns_window is not None and window != self.dns_window:
                for item in self.dns.finish():
                    self.store.event("CONTINUOUS_DNS_TRANSACTION", item)
                from soc_agent.security_ai.research.isolated_dns import IsolatedDNS

                self.dns = IsolatedDNS(str(self.epoch) + ":" + str(window))
            self.dns_window = window
            for item in self.dns.observe(packet, raw["sequence"]):
                self.store.event("CONTINUOUS_DNS_TRANSACTION", item)
            if self.last_event_ns is not None and ns < self.last_event_ns:
                self.metrics["source_gaps"] += 1
                await self.complete(self.aggregator.close("RESTART_GAP"), self.last_event_ns)
                self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
                raise ValueError("CONTINUOUS_CLOCK_REVERSED")
            self.last_event_ns = ns
            try:
                items = self.aggregator.add(packet, UUID(identity))
            except ValueError:
                await self.complete(self.aggregator.close("PACKET_LIMIT"), ns)
                raise
            await self.complete(items, ns)
        elif kind == "job":
            job = JOB.validate_python(raw["job"])
            if job.kind not in ("raw_dns", "stored_dns", "stored_records", "collector_error"):
                raise ValueError("CONTINUOUS_SOURCE_JOB_DOMAIN_NOT_ALLOWED")
            self.metrics["dns_inputs"] += len(job.messages) if job.kind == "raw_dns" else 0
            self.metrics["authentication_inputs"] += (
                sum(r.record_type == "authentication_event" for r in job.records)
                if job.kind == "stored_records"
                else 0
            )
            await self.handoff(job)
        elif kind == "excluded":
            self.metrics["excluded"] += 1
            if raw.get("affects_integrity") is not False:
                self.metrics["source_gaps"] += 1
                await self.complete(self.aggregator.close("RESTART_GAP"), self.last_event_ns or 0)
                self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
        else:
            raise ValueError("CONTINUOUS_SOURCE_RECORD_KIND")
        self.store.applied(raw["sequence"])

    async def project_dns(self, raw, *, recovering=False):
        """Durable metadata only; never manufactures a Replay/model job from DNS."""
        if self.config.source != "NATIVE_SERVICE" or self.dns_source is None:
            raise ValueError("CONTINUOUS_DNS_APPROVED_SOURCE_REQUIRED")
        if (
            raw.get("kind") != "native_dns"
            or raw.get("session") != str(self.dns_source.session.session_id)
            or raw.get("namespace") != self.config.namespace
            or type(raw.get("sequence")) is not int
            or raw["sequence"] != self.dns_sequence + 1
        ):
            raise ValueError("CONTINUOUS_DNS_SESSION_OR_SEQUENCE_BINDING")
        packet = PacketObservation.model_validate(raw["packet"])
        if (
            packet.interface_id != self.dns_source.session.interface_id
            or packet.timestamp_origin != "KERNEL_SO_TIMESTAMPNS"
            or packet.direction != "OUTBOUND"
            or 53 not in (packet.source_port, packet.destination_port)
            or packet.dns is not None
            and packet.dns.query_name is not None
        ):
            raise ValueError("CONTINUOUS_DNS_PACKET_BINDING")
        key = "dns:" + raw["session"] + ":" + str(raw["sequence"])
        retained_bytes = len(json.dumps(raw).encode())
        if (
            self.metrics["dns_metadata_bytes"] + retained_bytes
            > self.dns_source.session.policy.metadata_bytes
        ):
            self.metrics["dns_rejected"] += 1
            raise ValueError("CONTINUOUS_DNS_METADATA_LIMIT")
        if not recovering:
            fresh = await self.storage(self.store.retain_auxiliary, key, raw)
            if not fresh:
                raise ValueError("CONTINUOUS_DNS_DUPLICATE_SEQUENCE")
        self.metrics["dns_metadata_bytes"] += retained_bytes
        events = self.dns.observe(packet, raw["sequence"])
        self.dns_sequence = raw["sequence"]
        self.metrics["dns_inputs"] += 1
        for event in events:
            # Recovery replays the exact retained metadata through the same engine.
            # Event identity deduplicates persisted projections atomically with Audit.
            await self.storage(self.store.event_once, "CONTINUOUS_DNS_TRANSACTION", event)
            if self.investigations is not None and event["status"] == "MATCHED_RESPONSE":
                from soc_agent.continuous.investigation_models import InvestigationSource

                source = InvestigationSource(
                    incident_id=uuid5(NAMESPACE_URL, "continuous-dns:" + event["event_id"]),
                    role="DNS",
                    origin="REAL_NATIVE_DNS_METADATA",
                    namespace=self.config.namespace,
                    scope=self.config.input_sha256,
                    reference=event["event_id"],
                    observed_at=packet.timestamp,
                    target=digest(str(packet.destination_address)),
                    clock="UTC",
                    event_ns=event["event_ns"],
                    advisory=event,
                )
                await self.submit_investigation(source)

    async def submit_investigation(self, source):
        try:
            await self.storage(self.investigations.submit, source)
        except QueueFull:
            # The immutable source remains retained for explicit/restart recovery.
            # Backpressure must not repeat model inference or block Collector on LLM.
            await self.storage(
                self.store.event,
                "CONTINUOUS_ORCHESTRATION_BACKPRESSURE",
                dict(source=source.pin, disposition="RETAINED_NOT_DROPPED"),
            )

    async def collect_dns(self):
        try:
            async for packet in self.dns_source.events():
                await self.project_dns(
                    dict(
                        kind="native_dns",
                        session=str(self.dns_source.session.session_id),
                        namespace=self.config.namespace,
                        sequence=self.dns_source.sequence,
                        packet=packet.model_dump(mode="json"),
                    )
                )
            if not self.stop.is_set():
                raise ValueError("CONTINUOUS_DNS_SOURCE_EARLY_EXIT")
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, RuntimeError) as error:
            self.last_error = self.last_error or type(error).__name__ + ":" + str(error)
            raise

    async def project_journal(self, message):
        from soc_agent.continuous.authentication import normalized

        source = digest(self.journal.reader.identity)
        _, record = normalized(message, source)
        for job in self.auth.observe(record, source_digest=source):
            self.metrics["auth_windows"] += 1
            await self.handoff(job)
        self.metrics["authentication_inputs"] += 1

    async def collect_journal(self):
        self.journal_state = "RUNNING_STORED_OR_EXPLICIT_READER"
        try:
            while not self.stop.is_set():
                try:
                    polling = asyncio.create_task(asyncio.to_thread(self.journal.poll))
                    try:
                        await asyncio.shield(polling)
                    except asyncio.CancelledError:
                        # Join the bounded poll before publishing STOPPED or
                        # allowing a quiescent multi-database backup.
                        await asyncio.wait_for(
                            asyncio.shield(polling), self.config.shutdown_seconds
                        )
                        raise
                except QueueFull:
                    self.store.event("CONTINUOUS_JOURNAL_BACKPRESSURE", {})
                while not self.stop.is_set():
                    held = self.journal.claim()
                    if held is None:
                        break
                    claim, message = held
                    try:
                        fresh = self.store.retain_auxiliary(str(claim.event.event_id), message)
                        if fresh:
                            await self.project_journal(message)
                        self.journal.acknowledge_retained(claim)
                    except BaseException:
                        self.journal.queue.fail(claim, "WORKER_FAILURE")
                        raise
                await asyncio.sleep(self.config.heartbeat_seconds)
        finally:
            self.journal_state = "STOPPED"

    async def collect(self):
        try:
            # Replay restart configuration never grants Native reconnect/restart.
            max_restarts = (
                0 if self.config.source == "NATIVE_SERVICE" else self.config.collector_restarts
            )
            for attempt in range(max_restarts + 1):
                self.last_sequence = 0
                # Retained ingress rebuilt the pending flows before this first
                # collector start. Duplicate source delivery must not erase its
                # event-time witness and manufacture different final-window IDs.
                if attempt or not self.metrics["recovered_events"]:
                    self.last_event_ns = None
                self.collector_state = (
                    "RUNNING" if self.config.source == "NATIVE_SERVICE" else "RUNNING_REPLAY"
                )
                try:
                    async for raw in self.source.events():
                        if self.stop.is_set() and self.config.source != "NATIVE_SERVICE":
                            break
                        await self.observe(raw)
                        self.collector_event_unix = time.time()
                    self.collector_state = "STOPPED" if self.stop.is_set() else "EOF_NOT_LIVE"
                    break
                except (ValueError, OSError, RuntimeError) as error:
                    import traceback

                    if self.last_error is None:
                        self.last_error = type(error).__name__ + ":" + str(error)
                        self.collector_failure = dict(
                            code=str(error),
                            category=type(error).__name__,
                            origin=[
                                dict(
                                    file=Path(row.filename).name, function=row.name, line=row.lineno
                                )
                                for row in traceback.extract_tb(error.__traceback__)[-8:]
                            ],
                        )
                    self.metrics["invalid"] += 1
                    self.collector_failures += 1
                    await self.storage(
                        self.store.event,
                        "CONTINUOUS_COLLECTOR_FAILED",
                        dict(
                            attempt=attempt,
                            epoch=str(self.epoch),
                            first_error=self.last_error,
                            failure=self.collector_failure,
                        ),
                    )
                    await self.complete(
                        self.aggregator.close("RESTART_GAP"), self.last_event_ns or 0
                    )
                    self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
                    self.epoch = uuid4()
                    if attempt == max_restarts:
                        self.collector_state = "CIRCUIT_OPEN"
                        self.last_error = self.last_error or "CONTINUOUS_COLLECTOR_CIRCUIT_OPEN"
                        break
                    self.metrics["collector_restarts"] += 1
                    await asyncio.sleep(0.1)
            await self.complete(self.aggregator.close("SHUTDOWN"), self.last_event_ns or 0)
            if self.journal is None:
                for job in self.auth.close(self.auth_source_sha):
                    await self.handoff(job)
        finally:
            await self.source.close()
            self.done.set()

    async def start_analysis(self, path, body):
        """Keep a retained Native action pending without starting any model worker."""
        job = JOB.validate_json(body)
        if job.kind != "tcx_analysis":
            await self.analysis.start(path)
            return
        from soc_agent.security_ai.tcx_input import candidates

        receipts = candidates(job)[2]
        if job.origin == "REAL_NATIVE" and any(r["eligible"] for r in receipts):
            from soc_agent.security_ai.tcx_analysis import analysis_action

            pin = digest(job.model_dump(mode="json"))
            output = self.analysis.directory / ("run-" + pin)
            action = analysis_action(job, output)
            await self.storage(
                self.store.event,
                "CONTINUOUS_MODEL_APPROVAL_WAIT",
                dict(job=pin, action=action.model_dump(mode="json")),
            )
            while not self.stop.is_set():
                self.worker_state = "WAITING_EXACT_MODEL_ACTION_APPROVAL"
                self.worker_observed_unix = time.time()
                grant = (
                    self.config.native_model_approvals / (pin + ".json")
                    if self.config.native_model_approvals
                    else None
                )
                if grant is not None and grant.is_file():
                    break
                # The supervisor publishes the heartbeat at the configured rate.
                # Polling an approval file must not cause 10 durable DB writes/sec.
                await asyncio.sleep(0.1)
            if self.stop.is_set():
                raise asyncio.CancelledError
        await self.analysis.start_retained_tcx(path, approvals=self.config.native_model_approvals)

    async def consume(self):
        self.worker_state = "IDLE"
        while not self.stop.is_set():
            self.worker_observed_unix = time.time()
            if self.circuit:
                self.worker_state = "CIRCUIT_OPEN"
                await asyncio.sleep(0.1)
                continue
            claim = await self.storage(self.store.queue.claim)
            if claim is None:
                self.worker_state = "IDLE"
                await asyncio.sleep(0.05)
                continue
            try:
                self.worker_state = "ANALYZING"
                path = self.store.input_path(claim.event)
                body = read_local(path, 1024 * 1024)
                if digest(json.loads(body)) != dict(claim.event.normalized_fields)["job_digest"]:
                    raise ValueError("CONTINUOUS_INPUT_CHANGED")
                await self.start_analysis(path, body)
                # Observation of a live owned task is not a model progress claim.
                # Keep supervisor health fresh while the bounded CLI does its work.
                while not self.analysis.monitor.done():
                    self.worker_observed_unix = time.time()
                    await asyncio.wait(
                        {self.analysis.monitor}, timeout=self.config.heartbeat_seconds
                    )
                await self.analysis.monitor
                value = self.analysis.snapshot()
                outcome = value.get("result")
                if value["state"] != "COMPLETED" or not outcome:
                    raise ValueError("CONTINUOUS_MODEL_WORKER_FAILURE")
                if outcome["classification"] == "MODEL_ERROR":
                    raise ValueError("CONTINUOUS_MODEL_RESULT_FAILURE")
                self.metrics["predictions"] += outcome["inference_count"]
                self.metrics["incidents"] += 1
                self.last_results = (
                    self.last_results
                    + [
                        dict(
                            incident_id=outcome["incident_id"],
                            origins=outcome.get("input_origins", []),
                            domains=outcome.get("evidence_domains", []),
                            investigation=outcome.get("investigation_status", "UNKNOWN"),
                            classification=outcome["classification"],
                            eligibility=outcome["eligibility"],
                            llm_mode=outcome["llm_mode"],
                            output=value["output"],
                            predictions=outcome["predictions"],
                            response=outcome["response_status"],
                            audit=outcome["audit"],
                        )
                    ]
                )[-32:]
                if self.investigations is not None:
                    from soc_agent.continuous.investigation import from_analysis

                    source = await self.storage(
                        from_analysis,
                        Path(value["output"]),
                        scope=self.config.input_sha256,
                        namespace=self.config.namespace,
                    )
                    await self.submit_investigation(source)
                await self.storage(
                    self.store.event,
                    "CONTINUOUS_ANALYSIS_COMPLETED",
                    dict(
                        event=str(claim.event.event_id),
                        output=value["output"],
                        incident=outcome["incident_id"],
                    ),
                )
                await self.storage(
                    self.store.queue.finish,
                    claim,
                    dict(
                        inference="VERIFIED_RETAINED_EVIDENCE",
                        incident_id=outcome["incident_id"],
                        workflow="COMPLETED",
                        human_boundary="WRITE_DENIED",
                    ),
                )
                self.worker_failures = 0
            except asyncio.CancelledError:
                self.approval_wait_cancelled = (
                    self.stop.is_set()
                    and self.worker_state == "WAITING_EXACT_MODEL_ACTION_APPROVAL"
                    and (
                        self.analysis.process is None
                        or (
                            self.analysis.process.returncode is not None
                            and self.analysis.cleanup == "VERIFIED"
                        )
                    )
                )
                await self.storage(
                    self.store.queue.fail,
                    claim,
                    "INFERENCE_UNAVAILABLE" if self.approval_wait_cancelled else "WORKER_FAILURE",
                )
                await self.storage(
                    self.store.event,
                    "CONTINUOUS_MODEL_APPROVAL_WAIT_STOPPED"
                    if self.approval_wait_cancelled
                    else "CONTINUOUS_WORKER_CANCELLED_UNKNOWN",
                    dict(event=str(claim.event.event_id)),
                )
                raise
            except (ValueError, OSError, RuntimeError):
                self.metrics["model_errors"] += 1
                self.worker_failures += 1
                await self.storage(self.store.queue.fail, claim, "WORKER_FAILURE")
                await self.storage(
                    self.store.event,
                    "CONTINUOUS_WORKER_FAILED_NO_RETRY",
                    dict(event=str(claim.event.event_id), failures=self.worker_failures),
                )
                if self.worker_failures >= self.config.worker_circuit_failures:
                    self.circuit = True
                    self.last_error = "CONTINUOUS_MODEL_CIRCUIT_OPEN"
            await self.publish()

    async def run(self):
        if os.geteuid() == 0:
            raise ValueError("CONTINUOUS_AI_SERVICE_REQUIRES_ORDINARY_UID")
        require_source_authority(self.config)
        with exclusive_runtime_lock(self.directory / "service.lock"):
            collector = consumer = journal = dns_task = investigation_worker = None
            primary = None
            try:
                from soc_agent.continuous.investigation import consume as investigate
                from soc_agent.continuous.investigation_store import InvestigationTasks

                self.investigations = await self.storage(InvestigationTasks, self.store)
                investigation_worker = asyncio.create_task(
                    investigate(self.investigations, self.stop, self.investigation_progress)
                )
                if self.config.dns_session and self.dns_source is None:
                    from soc_agent.continuous.dns_source import DNSProducer

                    self.dns_source = DNSProducer(
                        self.config.dns_session, self.config.dns_session_sha256
                    )
                self.store.control()
                self.store.queue.recover()
                self.store.event(
                    "CONTINUOUS_SERVICE_STARTED",
                    dict(pid=os.getpid(), epoch=str(self.epoch), source=self.config.source),
                )
                if self.config.source != "NATIVE_SERVICE":
                    for retained in self.store.retained():
                        await self.observe(retained, recovering=True)
                        self.metrics["recovered_events"] += 1
                    self.store.event(
                        "CONTINUOUS_INGRESS_REBUILT", dict(count=self.metrics["recovered_events"])
                    )
                if self.config.source == "NATIVE_SERVICE":
                    for raw in self.store.auxiliary():
                        if raw.get("kind") in ("native_tcx", "native_seal"):
                            jobs, _ = self.capture_windows.accept(raw)
                            for job in jobs:
                                await self.handoff(job)
                        elif raw.get("kind") == "native_dns":
                            await self.project_dns(raw, recovering=True)
                if self.journal:
                    self.journal.recover()
                    for retained in self.store.auxiliary():
                        if retained.get("kind") not in ("native_tcx", "native_seal", "native_dns"):
                            await self.project_journal(retained)
                    journal = asyncio.create_task(self.collect_journal())
                if self.dns_source:
                    dns_task = asyncio.create_task(self.collect_dns())
                collector = asyncio.create_task(self.collect())
                consumer = asyncio.create_task(self.consume())
                while not self.stop.is_set():
                    current = await self.storage(self.store.state)
                    if current["stop_requested"]:
                        self.stop_reason = "OPERATOR_REQUEST"
                        await self.storage(
                            self.store.update, self.snapshot() | dict(state="STOPPING")
                        )
                        if self.config.source == "NATIVE_SERVICE":
                            await self.source.request_stop()
                        self.stop.set()
                        break
                    if current["reset_worker"]:
                        self.circuit = False
                        self.worker_failures = 0
                        self.store.control()
                        self.store.event("CONTINUOUS_WORKER_RESET", {})
                    if investigation_worker.done():
                        investigation_worker.result()
                        if not self.stop.is_set():
                            raise ValueError("CONTINUOUS_INVESTIGATION_WORKER_EXITED")
                    self.investigation_snapshot = await self.storage(self.investigations.snapshot)
                    if consumer.done():
                        consumer.result()
                        raise ValueError("CONTINUOUS_WORKER_TASK_EXITED")
                    if collector.done():
                        collector.result()
                        if self.config.source == "NATIVE_SERVICE" and not self.stop.is_set():
                            raise ValueError(
                                (getattr(self.source, "failure", None) or {}).get("code")
                                or "CONTINUOUS_NATIVE_COLLECTOR_EARLY_EXIT"
                            )
                    if journal and journal.done():
                        journal.result()
                        raise ValueError("CONTINUOUS_JOURNAL_TASK_EXITED")
                    if dns_task and dns_task.done():
                        dns_task.result()
                        raise ValueError("CONTINUOUS_DNS_TASK_EXITED")
                    size = sum(p.stat().st_size for p in self.directory.rglob("*") if p.is_file())
                    if size >= self.config.max_storage_bytes:
                        raise ValueError("CONTINUOUS_STORAGE_LIMIT_REQUIRES_ARCHIVAL")
                    await self.publish()
                    await asyncio.sleep(self.config.heartbeat_seconds)
            except BaseException as error:
                primary = error
                self.last_error = self.last_error or type(error).__name__
                raise
            finally:
                # A storage/consumer failure must never bypass owned process cleanup.
                # Collect cleanup failures separately and preserve the first exception.
                self.stop.set()
                failures = []
                if self.dns_source:
                    try:
                        await self.dns_source.request_stop()
                        if dns_task and not dns_task.done():
                            await asyncio.wait_for(
                                asyncio.shield(dns_task), self.config.shutdown_seconds
                            )
                    except BaseException as error:
                        if error is not primary:
                            failures.append(error)
                    finally:
                        if dns_task:
                            dns_task.cancel()
                            result = await asyncio.gather(dns_task, return_exceptions=True)
                            failures.extend(
                                e
                                for e in result
                                if isinstance(e, BaseException)
                                and not isinstance(e, asyncio.CancelledError)
                                and e is not primary
                                and e not in failures
                            )
                        try:
                            await self.dns_source.close()
                            if self.dns_source.snapshot["cleanup"] != "VERIFIED":
                                raise ValueError("CONTINUOUS_DNS_CLEANUP_UNVERIFIED")
                        except BaseException as error:
                            failures.append(error)
                if self.config.source == "NATIVE_SERVICE" and collector and not collector.done():
                    # SIGTERM sets stop directly, unlike the CLI control flag.
                    # Keep the receiver alive for the final seal and bound STOP ACK
                    # before cancelling it or closing the owner's socket.
                    try:
                        await self.source.request_stop()
                    except BaseException as error:
                        failures.append(error)
                if collector:
                    collector.cancel()
                    collector_exit = await asyncio.gather(collector, return_exceptions=True)
                    failures.extend(
                        e
                        for e in collector_exit
                        if isinstance(e, BaseException)
                        and not isinstance(e, asyncio.CancelledError)
                        and e is not primary
                    )
                if journal:
                    journal.cancel()
                    journal_exit = await asyncio.gather(journal, return_exceptions=True)
                    failures.extend(
                        e
                        for e in journal_exit
                        if isinstance(e, BaseException)
                        and not isinstance(e, asyncio.CancelledError)
                    )
                if consumer:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(consumer), self.config.shutdown_seconds
                        )
                    except BaseException as error:
                        if isinstance(error, TimeoutError):
                            consumer.cancel()
                            await asyncio.gather(consumer, return_exceptions=True)
                        elif error is not primary and not (
                            isinstance(error, asyncio.CancelledError)
                            and self.approval_wait_cancelled
                            and primary is None
                        ):
                            failures.append(error)
                if investigation_worker:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(investigation_worker), self.config.shutdown_seconds
                        )
                    except TimeoutError:
                        investigation_worker.cancel()
                        await asyncio.gather(investigation_worker, return_exceptions=True)
                        self.investigation_progress.update(
                            state="CANCELLED_CHECKPOINT_REVIEW_REQUIRED"
                        )
                    except BaseException as error:
                        if error is not primary:
                            failures.append(error)
                    self.investigation_snapshot = await self.storage(self.investigations.snapshot)
                for close in (self.source.close, self.analysis.close):
                    try:
                        await close()
                    except BaseException as error:
                        failures.append(error)
                if (
                    self.config.source == "NATIVE_SERVICE"
                    and getattr(self.source, "remote_cleanup", "UNKNOWN") != "VERIFIED"
                ):
                    # The producer attempts its bounded failure STOP before it
                    # closes. Local closure still cannot replace a bound ACK.
                    failures.append(ValueError("CONTINUOUS_REMOTE_CLEANUP_UNVERIFIED"))
                flush_error = None
                try:
                    for event in self.dns.finish(aborted=True):
                        self.store.event_once("CONTINUOUS_DNS_TRANSACTION", event)
                    await self.complete(self.aggregator.close("SHUTDOWN"), self.last_event_ns or 0)
                    for job in self.native_windows.close():
                        await self.handoff(job)
                    for job in self.auth.close(self.auth_source_sha):
                        await self.handoff(job)
                except BaseException as error:
                    flush_error = type(error).__name__
                    if primary is None:
                        failures.append(error)
                try:
                    cleanup = "UNVERIFIED" if failures else "VERIFIED"
                    if failures and self.last_error is None:
                        self.last_error = type(failures[0]).__name__ + ":" + str(failures[0])[:1000]
                    if self.config.source == "NATIVE_SERVICE":
                        self.store.event(
                            "CONTINUOUS_TCX_CLEANUP_EVIDENCE",
                            dict(
                                first_error=self.last_error,
                                collector_cleanup=getattr(self.source, "remote_cleanup", "UNKNOWN"),
                                evidence=getattr(self.source, "cleanup_evidence", {}),
                            ),
                        )
                    self.store.event(
                        "CONTINUOUS_SERVICE_STOPPED",
                        dict(
                            epoch=str(self.epoch),
                            metrics=dict(self.metrics),
                            first_error=self.last_error,
                            final_flush_error=flush_error,
                            cleanup=cleanup,
                            secondary_errors=[
                                dict(category=type(e).__name__, code=str(e)[:1000])
                                for e in failures
                            ],
                        ),
                    )
                    self.store.update(
                        self.snapshot()
                        | dict(
                            state="STOPPED" if cleanup == "VERIFIED" else "DEGRADED",
                            collector="STOPPED",
                            worker="STOPPED",
                            cleanup=cleanup,
                            final_flush="FAILED" if flush_error else "VERIFIED",
                            collection_live=False,
                            queue=self.store.queue.counts(),
                        )
                    )
                except BaseException as error:
                    # Evidence cannot claim verified cleanup if its write failed;
                    # the last heartbeat remains stale/unknown for status readers.
                    failures.append(error)
                if primary is None and failures:
                    raise failures[0]
