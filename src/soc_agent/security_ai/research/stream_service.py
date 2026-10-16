"""Managed mode of the existing Network companion; no privileged subprocess launch."""

import asyncio
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4, uuid5

from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.network_capture.stream_session import (
    StreamPolicy,
    instructions,
    load,
    prepare,
    unprivileged,
)
from soc_agent.security_ai.operational.network_capture.stream_transport import StreamingCapture
from soc_agent.security_ai.operational.network_capture.streaming_flow import (
    PacketTimeReversed,
    StreamingFlows,
)
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.live_input import lifecycle_eligible
from soc_agent.security_ai.research.live_service import LiveResearch
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_store import StreamStore


class StreamResearch(LiveResearch):
    capacity = 256

    def __init__(self, directory, *, paths=None, timeout=30):
        super().__init__(directory, paths=paths, timeout=timeout)
        self.adapter = ResearchAdapter(
            self.directory, paths=paths, timeout=timeout, live_metadata=True, transient_inputs=True
        )
        self.expected_values = None
        self.window = None

    def attempt_document(self, request, key):
        return dict(
            key=key,
            request=dict(
                profile=request.profile,
                invocation_id=str(request.invocation_id),
                request_digest=digest(request.model_dump(mode="json")),
                flow_id=request.flow_id,
                capture_session=str(request.capture_session),
                origin=request.origin,
            ),
            created_at=datetime.now(UTC).isoformat(),
        )

    def validate_receipt(self, request, receipt):
        if self.expected_values is None or receipt.feature_values != self.expected_values:
            raise ValueError("STREAM_INCREMENTAL_PRODUCER_PARITY_FAILED")
        if request.origin == "NATIVE_AF_PACKET":
            self.adapter.authorize_live(request)


class StreamingMonitoring:
    """GUI-owned managed mode reusing Queue/SourceStore, reader and research ledger.

    Native input is allowed only through the new peer-verified helper contract.
    Fixture input is explicit and cannot authorize a Native request. Packet-time
    expiry and legacy per-flow limits are preserved; old sessions are untouched.
    """

    def __init__(self, directory, *, paths=None):
        self.root = directory / "streaming-network"
        self.paths = paths
        self.directory = self.session = self.capture = self.store = self.demo = self.task = None
        self.consumer = None
        self.state = "STOPPED"
        self.last_error = None
        self.stop_requested = False
        self.aborted = False
        self.fixture = False
        self.done = asyncio.Event()
        self.policy = StreamPolicy()
        self.metrics = {}
        self.preparing = False
        self.inference_blocked = False
        self.flow_count = self.eligible = self.excluded = 0
        self.started_at = None
        self.cpu_start = 0
        self.windows = {}
        self.current = None
        self.stop_sent = False
        self.failure_context = None

    def _release_lock(self):
        if getattr(self, "writer_lock", None) is not None:
            self.writer_lock.__exit__(None, None, None)
            self.writer_lock = None

    async def _prepare_failed(self):
        self.done.set()
        if self.consumer is not None:
            self.consumer.cancel()
            await asyncio.gather(self.consumer, return_exceptions=True)
        if self.capture is not None:
            await asyncio.to_thread(self.capture.close)
        if self.demo is not None:
            await self.demo.stop()
        self._release_lock()

    async def start(self, profiles=("quality", "edge"), *, policy=None):
        if self.preparing or (self.task is not None and not self.task.done()):
            raise ValueError("STREAM_ALREADY_ACTIVE")
        unprivileged()
        self.preparing = True
        try:
            await self._prepare(profiles, policy or StreamPolicy(), fixture=False)
            if self.stop_requested:
                await self._prepare_failed()
                self.state = "STOPPED"
                return {"status": "STOPPED", "listener_ready": False}
            self.capture = StreamingCapture(self.directory, self.session)
            self.stop_sent = False
            self.state = "AUTHENTICATION_REQUIRED"
            self.task = asyncio.create_task(self._native())
            return self.command(str(self.session.session_id))
        except (OSError, ValueError, StorageError):
            await self._prepare_failed()
            self.state = "ERROR"
            self.last_error = "STREAM_PREPARE_FAILED"
            return {"status": "BLOCKED", "last_error": self.last_error, "listener_ready": False}
        finally:
            self.preparing = False

    async def _prepare(self, profiles, policy, *, fixture):
        if (
            not profiles
            or len(set(profiles)) != len(profiles)
            or any(p not in ("quality", "edge") for p in profiles)
        ):
            raise ValueError("STREAM_PROFILE_INVALID")
        create_private_directory(self.root)
        if len(list(self.root.glob("session-*"))) >= 8:
            raise ValueError("STREAM_ARCHIVAL_REQUIRED")
        self.directory = self.root / ("session-" + uuid4().hex)
        self.policy = StreamPolicy.model_validate(policy.model_dump())
        self.fixture = fixture
        self.capture = None
        self.session = prepare(self.directory, self.policy)
        self.profiles = profiles
        self.aborted = self.stop_requested = False
        self.last_error = None
        self.stop_sent = False
        self.failure_context = None
        self.done = asyncio.Event()
        self.current = None
        self.aggregator = StreamingFlows(
            max_flows=policy.active_flows, metadata_bytes=policy.metadata_bytes
        )
        self.windows = {}
        self.flow_count = self.eligible = self.excluded = 0
        self.metrics = dict(
            packets_collected=0,
            flow_records=0,
            queue_backlog=0,
            gap_count=0,
            capture_drops=None,
            finalization="RUNNING",
            input_origin="FIXTURE" if fixture else "NATIVE_AF_PACKET",
            timestamp_integrity="UNKNOWN",
            packet_sequence=None,
            abort_reason=None,
            inference_count=0,
            advisory_latency_seconds=None,
        )
        self.store = StreamStore(self.directory, self.session, fixture=fixture, create=True)
        self.writer_lock = exclusive_runtime_lock(self.directory / "runtime/writer.lock")
        self.writer_lock.__enter__()
        self.demo = StreamResearch(self.directory, paths=self.paths)
        self.demo.adapter.authorize_live = self.authorize
        ready = await self.demo.start()
        if ready.get("status") == "BLOCKED":
            raise ValueError("STREAM_ARTIFACT_ENVIRONMENT_BLOCKED")
        self.started_at = time.monotonic()
        self.cpu_start = time.process_time()
        self.last_publish = 0
        self.model_attempts = 0
        self.sequence = 0
        self.inference_blocked = False
        self.consumer = asyncio.create_task(self._consume())
        self.store.runtime.event(
            "STREAM_STARTED",
            dict(
                session_digest=digest(self.session.model_dump(mode="json")),
                policy=policy.model_dump(mode="json"),
                origin=self.metrics["input_origin"],
            ),
        )

    async def start_fixture(
        self, source, *, profiles=("quality", "edge"), policy=None, model_adapter=None
    ):
        if self.preparing or (self.task is not None and not self.task.done()):
            raise ValueError("STREAM_ALREADY_ACTIVE")
        self.preparing = True
        try:
            await self._prepare(profiles, policy or StreamPolicy(), fixture=True)
            if model_adapter is not None:
                self.demo.adapter = model_adapter
            self.state = "FIXTURE_STREAMING"
            self.task = asyncio.create_task(self._fixture(source))
            return self.snapshot()
        except (OSError, ValueError, StorageError):
            await self._prepare_failed()
            raise
        finally:
            self.preparing = False

    async def _fixture(self, source):
        try:
            async for packet in source:
                if self.stop_requested or self.aborted:
                    break
                await self.observe(packet, self.sequence + 1)
                if time.monotonic() - self.started_at >= self.policy.seconds:
                    break
            await self._finalize()
        except (ValueError, OSError, StorageError, RuntimeError) as error:
            await self._failure(error)
        finally:
            self.done.set()
            self._release_lock()

    async def _native(self):
        try:
            await asyncio.wait_for(asyncio.to_thread(self.capture.handshake), 120)
            self.capture.start_reader()
            self.state = "LIVE_COLLECTION"
            self.started_at = time.monotonic()
            self.cpu_start = time.process_time()
            self.store.runtime.event(
                "STREAM_HELPER_READY",
                dict(
                    ready=self.capture.ready.model_dump(mode="json"),
                    session_digest=digest(self.session.model_dump(mode="json")),
                ),
            )
            while not self.aborted:
                packet = await asyncio.to_thread(self.capture.receive)
                if packet is not None:
                    await self.observe(packet, self.capture.last_seal[1])
                elif self.capture.terminal is not None:
                    # Reader may have enqueued PACKETs and CLOSED after receive()
                    # returned an empty queue. Drain that prefix before validating
                    # completion; CLOSED alone is not a persistence acknowledgement.
                    if not self.capture.packets.empty():
                        continue
                    if not self.capture.completion_verified():
                        raise ValueError("STREAM_CAPTURE_COMPLETION_UNVERIFIED")
                    break
                else:
                    await asyncio.sleep(0.01)
                    await self.publish()
                if self.stop_requested and not getattr(self, "stop_sent", False):
                    self.capture.request_stop()
                    self.stop_sent = True
                if time.monotonic() - self.started_at > self.policy.seconds + 2:
                    raise ValueError("STREAM_HELPER_DEADLINE_EXCEEDED")
            if not self.aborted:
                await self._finalize()
        except (ValueError, OSError, StorageError, RuntimeError) as error:
            await self._failure(error)
        finally:
            self.done.set()
            self._release_lock()
            if self.capture is not None:
                await asyncio.to_thread(
                    self.capture.close,
                    reason="STREAM_COMPLETED" if self.state == "STOPPED" else "STREAM_TASK_EXIT",
                )

    async def observe(self, packet, counter_sequence):
        if self.aborted:
            raise ValueError("STREAM_ABORTED")
        if (
            packet.interface_id != self.session.interface_id
            or (packet.timestamp_origin == "FIXTURE") != self.fixture
            or packet.dns is not None
        ):
            raise ValueError("STREAM_SOURCE_ORIGIN_MISMATCH")
        self.sequence += 1
        self.metrics["packet_sequence"] = self.sequence
        identity = uuid5(self.session.session_id, str(self.sequence))
        try:
            completed = self.aggregator.add(packet, identity)
        except PacketTimeReversed as error:
            # Comparison evidence, not causal attribution. Hash the bidirectional
            # flow key; do not retain addresses, payload, or corrected timestamps.
            self.metrics["timestamp_integrity"] = "FAILED_EVENT_TIME_ORDER"
            self.failure_context = dict(
                packet_sequence=self.sequence,
                helper_packet_sequence=self.capture.last_seal[0] if self.capture else None,
                counter_sequence=counter_sequence,
                previous_event_ns=error.previous_ns,
                rejected_event_ns=error.rejected_ns,
                regression_ns=error.previous_ns - error.rejected_ns,
                ordering_scope=error.scope,
                flow_key_digest=digest(self.aggregator.table.key(packet)),
                direction=packet.direction,
                timestamp_origin=packet.timestamp_origin,
                source_origin=self.metrics["input_origin"],
                root_cause="UNKNOWN",
            )
            raise
        self.metrics["timestamp_integrity"] = "ORDERED_PREFIX_ONLY"
        self.metrics["packets_collected"] += 1
        for item in completed:
            self.flow_count += 1
            window = (1, counter_sequence)
            if lifecycle_eligible(item.flow.close_reason):
                self.eligible += 1
                event = await asyncio.to_thread(self.store.commit, item, window, enqueue=False)
                self.windows[item.flow.flow_id] = event.source_digest
                if not await asyncio.to_thread(self.store.queue.enqueue, event):
                    raise ValueError("STREAM_DUPLICATE_FLOW_HANDOFF")
            else:
                self.excluded += 1
                await asyncio.to_thread(
                    self.store.runtime.event,
                    "STREAM_FLOW_EXCLUDED",
                    dict(
                        flow_id=item.flow.flow_id,
                        reason=item.flow.close_reason,
                        packets=len(item.packets),
                    ),
                )
        await self.publish()

    async def _consume(self):
        try:
            while not self.done.is_set() or self.store.queue.counts().get("PENDING", 0):
                if self.aborted:
                    return
                claim = await asyncio.to_thread(self.store.queue.claim)
                if claim is None:
                    await asyncio.sleep(0.05)
                    continue
                self.current = claim
                outcomes = []
                try:
                    for profile in self.profiles:
                        if self.inference_blocked:
                            raise ValueError("STREAM_CIRCUIT_OPEN_NO_RETRY")
                        if self.model_attempts >= self.policy.max_inferences:
                            raise ValueError("STREAM_MODEL_BUDGET_EXHAUSTED")
                        request, env = await asyncio.to_thread(
                            self.store.load, claim.event, profile
                        )
                        self.demo.expected_values = env.values
                        inference_started = time.monotonic()
                        self.demo.window = (env.counter_start, env.counter_end)
                        self.current_request = request
                        self.model_attempts += 1
                        key = digest(
                            dict(
                                session=str(request.capture_session),
                                flow=request.flow_id,
                                profile=profile,
                            )
                        )
                        result = await self.demo.dispatch(request, key)
                        if result.get("status") == "COMPLETE" and result.get("record", {}).get(
                            "receipt"
                        ):
                            self.metrics["inference_count"] += 1
                            self.metrics["advisory_latency_seconds"] = (
                                time.monotonic() - inference_started
                            )
                        outcomes.append(result["status"])
                        if result.get("status") not in ("COMPLETE", "CACHED_NO_NEW_INFERENCE"):
                            raise ValueError("STREAM_MODEL_UNKNOWN_NO_RETRY")
                    await asyncio.to_thread(self.store.finish, claim, "RESEARCH_COMPLETE")
                except (ValueError, OSError, StorageError) as error:
                    await asyncio.to_thread(self.store.finish, claim, "UNKNOWN_NO_RETRY")
                    self.inference_blocked = True
                    self.last_error = type(error).__name__ + ":STREAM_MODEL_OR_INPUT_FAILURE"
                finally:
                    self.windows.pop(dict(claim.event.normalized_fields)["flow_id"], None)
                    self.current = None
                    self.current_request = None
                    request = env = None
        except asyncio.CancelledError:
            if self.current is not None:
                await asyncio.to_thread(
                    self.store.finish, self.current, "UNKNOWN_CANCELLED_NO_RETRY"
                )
                self.current = None
            raise
        except (ValueError, OSError, StorageError, RuntimeError) as error:
            await self._failure(error, from_consumer=True)

    def authorize(self, request):
        if (
            self.fixture
            or self.aborted
            or not isinstance(self.capture, StreamingCapture)
            or self.capture.ready is None
            or self.capture.reader_failed()
            or self.capture.counter_issue is not None
            or self.current is None
        ):
            raise ValueError("STREAM_AUTHENTICATED_COUNTER_WINDOW_REQUIRED")
        if self.windows.get(request.flow_id) != self.current.event.source_digest:
            raise ValueError("STREAM_UNREGISTERED_SOURCE_WINDOW")
        expected, env = self.store.load(self.current.event, request.profile)
        expected = expected.model_copy(update={"invocation_id": request.invocation_id})
        if (
            expected != request
            or self.capture.counter_sequence < env.counter_end
            or self.capture.counter_totals[1] != 0
        ):
            raise ValueError("STREAM_SOURCE_WINDOW_BINDING_MISMATCH")
        if self.capture.terminal is not None and (
            self.capture.terminal.error is not None
            or self.capture.terminal.counter_status != "COUNTER_VERIFIED"
        ):
            raise ValueError("STREAM_FINAL_COUNTER_INVALID")

    async def publish(self, *, force=False):
        now = time.monotonic()
        if not force and now - self.last_publish < 1:
            return
        self.last_publish = now
        elapsed = now - self.started_at
        rss = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        cpu = time.process_time() - self.cpu_start
        if rss > self.policy.rss_bytes or cpu > self.policy.controller_cpu_seconds:
            raise ValueError("STREAM_CONTROLLER_RESOURCE_LIMIT")
        disk = sum(p.stat().st_size for p in self.directory.rglob("*") if p.is_file())
        if disk > self.policy.disk_bytes:
            raise ValueError("STREAM_DISK_RETENTION_LIMIT")
        self.metrics.update(
            last_error=self.last_error,
            collection_state=self.state,
            flow_records=self.flow_count,
            eligible_flows=self.eligible,
            rejected_flows=self.excluded,
            active_flows=len(self.aggregator.table.flows),
            retained_metadata_bytes=self.aggregator.bytes,
            peak_metadata_bytes=self.aggregator.peak_bytes,
            capture_uptime_seconds=elapsed,
            packets_per_second=self.metrics["packets_collected"] / elapsed if elapsed else None,
            flows_per_minute=self.flow_count * 60 / elapsed if elapsed else None,
            eligible_flows_per_minute=self.eligible * 60 / elapsed if elapsed else None,
            inferences_per_minute=self.metrics["inference_count"] * 60 / elapsed
            if elapsed
            else None,
            runtime_rss_bytes=rss,
            runtime_cpu_seconds=cpu,
            disk_bytes=disk,
            queue_backlog=sum(
                v for k, v in self.store.queue.counts().items() if k in ("PENDING", "CLAIMED")
            ),
        )
        if self.capture is not None:
            self.metrics.update(self.capture.extra_metrics())
        await asyncio.to_thread(self.store.runtime.update, network=dict(self.metrics))

    async def _finalize(self):
        self.state = "STREAM_DRAINING"
        for item in self.aggregator.close():
            self.excluded += 1
            self.flow_count += 1
            await asyncio.to_thread(
                self.store.runtime.event,
                "STREAM_FLOW_EXCLUDED",
                dict(flow_id=item.flow.flow_id, reason="SHUTDOWN", packets=len(item.packets)),
            )
        self.done.set()
        try:
            await asyncio.wait_for(self.consumer, self.policy.graceful_seconds)
        except TimeoutError:
            self.last_error = "STREAM_GRACEFUL_DEADLINE_UNKNOWN_NO_RETRY"
            self.windows.clear()
            await self.demo.stop()
            self.store.recover_no_retry()
        if self.aborted:
            return
        self.metrics["finalization"] = "VERIFIED" if not self.last_error else "PARTIAL"
        self.store.runtime.event(
            "STREAM_STOPPED",
            dict(
                finalization=self.metrics["finalization"],
                counter_window_scope="PER_FLOW_NOT_FUTURE_SESSION",
                open_flows_disposition="SHUTDOWN_NOT_INFERABLE",
            ),
        )
        self.windows.clear()
        await self.demo.stop()
        self.state = "STOPPED"
        await self.publish(force=True)

    async def _failure(self, error, *, from_consumer=False):
        self.aborted = True
        self.last_error = (
            str(error)
            if re.fullmatch(r"[A-Z0-9_:]{1,128}", str(error))
            else "STREAM_INPUT_OR_STORAGE_VALIDATION_FAILED"
        )
        self.state = "ERROR"
        self.metrics["abort_reason"] = self.last_error
        self.metrics["finalization"] = "BLOCKED"
        self.metrics["gap_count"] += 1
        self.aggregator.close("RESTART_GAP")
        self.windows.clear()
        self.done.set()
        if self.capture is not None:
            self.metrics.update(self.capture.extra_metrics())
            self.metrics["unprocessed_packets_at_abort"] = self.capture.packets.qsize()
            self.metrics["closed_status"] = (
                "VERIFIED" if self.capture.terminal is not None else "MISSING_OR_REJECTED"
            )
            self.metrics["final_counter_status"] = (
                self.capture.terminal.counter_status
                if self.capture.terminal is not None
                else "UNKNOWN"
            )
            await asyncio.to_thread(
                self.capture.close, reason="CONTROLLER_ABORT:" + self.last_error
            )
        await self.demo.stop()
        if (
            not from_consumer
            and self.consumer is not None
            and self.consumer is not asyncio.current_task()
        ):
            self.consumer.cancel()
            await asyncio.gather(self.consumer, return_exceptions=True)
        self.store.runtime.event(
            "STREAM_ABORTED",
            dict(
                error=self.last_error,
                active_metadata_released=True,
                automatic_retry=False,
                time_context=self.failure_context,
                rejected_closed_digest=self.metrics.get("rejected_closed_digest"),
            ),
        )
        try:
            self.store.recover_no_retry()
        except (ValueError, OSError, StorageError):
            self.last_error = "STREAM_RECOVERY_REVIEW_REQUIRED"
        # Persist the terminal failure, not the last periodic RUNNING sample.
        # Do not call publish(): the failure itself may be a resource budget breach.
        self.metrics.update(
            last_error=self.last_error,
            collection_state=self.state,
            time_context=self.failure_context,
            active_flows=0,
            retained_metadata_bytes=0,
            queue_backlog=sum(
                v for k, v in self.store.queue.counts().items() if k in ("PENDING", "CLAIMED")
            ),
        )
        await asyncio.to_thread(self.store.runtime.update, network=dict(self.metrics))

    async def stop(self, *, abort=False):
        self.stop_requested = True
        if self.task is None or self.task.done():
            return self.snapshot()
        if self.state == "AUTHENTICATION_REQUIRED" or abort:
            cancelled_preparation = self.state == "AUTHENTICATION_REQUIRED" and not abort
            await self._failure(ValueError("STREAM_EXPLICIT_ABORT_NO_RETRY"))
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
            if cancelled_preparation:
                self.state = "STOPPED"
                self.last_error = None
                self.metrics["finalization"] = "CANCELLED_NOT_CAPTURE_VERIFIED"
                self.metrics.update(last_error=None, collection_state=self.state)
                self.store.runtime.event(
                    "STREAM_PREPARATION_CANCELLED", {"capture_verified": False}
                )
                await asyncio.to_thread(self.store.runtime.update, network=dict(self.metrics))
        else:
            if not self.fixture and not self.stop_sent:
                # Stop new capture promptly, even while observe() is awaiting SQLite.
                # Keep the reader/channel open for CLOSED and already queued metadata.
                self.stop_sent = True
                try:
                    self.capture.request_stop()
                except (OSError, ValueError) as error:
                    await self._failure(error)
                else:
                    self.store.runtime.event("STREAM_STOP_DRAIN_REQUESTED", {})
            try:
                await asyncio.wait_for(asyncio.shield(self.task), self.policy.graceful_seconds + 3)
            except TimeoutError:
                await self._failure(ValueError("STREAM_STOP_DEADLINE_EXCEEDED"))
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
        return self.snapshot()

    def command(self, session_id):
        if (
            self.session is None
            or str(self.session.session_id) != session_id
            or self.fixture
            or self.state != "AUTHENTICATION_REQUIRED"
            or self.capture is None
            or not self.capture.listener_ready()
            or self.task is None
            or self.task.done()
        ):
            return {"status": "BLOCKED", "error": "STREAM_LISTENER_NOT_READY"}
        try:
            if load(self.directory) != self.session:
                raise ValueError("STREAM_SESSION_POLICY_CHANGED")
        except (ValueError, OSError, StorageError):
            return {"status": "BLOCKED", "error": "STREAM_SESSION_IDENTITY_CHANGED"}
        return {**instructions(self.directory, self.session), "listener_ready": True}

    async def restore_latest(self):
        """Explicit no-retry recovery of this managed mode only; never starts capture."""
        if self.preparing or (self.task is not None and not self.task.done()):
            raise ValueError("STREAM_ALREADY_ACTIVE")
        directories = sorted(self.root.glob("session-*"), key=lambda p: p.stat().st_mtime)
        if not directories:
            return self.snapshot()
        self.directory = directories[-1]
        self.session = load(self.directory)
        self.policy = self.session.policy
        from soc_agent.linux_runtime.store import RuntimeStore

        runtime = RuntimeStore(self.directory / "runtime")
        with runtime.database.transaction(write=False) as c:
            lifecycle = [
                json.loads(r[0])
                for r in c.execute(
                    "SELECT payload FROM monitor_audit WHERE "
                    "json_extract(payload,'$.kind') IN "
                    "('STREAM_ABORTED','STREAM_STOPPED','STREAM_PREPARATION_CANCELLED') "
                    "ORDER BY sequence"
                )
            ]
            started = [
                json.loads(r[0])["details"]
                for r in c.execute(
                    "SELECT payload FROM monitor_audit WHERE "
                    "json_extract(payload,'$.kind')='STREAM_STARTED'"
                )
            ]
        if len(started) != 1:
            raise ValueError("STREAM_SESSION_ORIGIN_UNVERIFIED")
        self.fixture = started[0]["origin"] == "FIXTURE"
        self.capture = self.task = None
        self.windows = {}
        self.store = StreamStore(self.directory, self.session, fixture=self.fixture)
        with exclusive_runtime_lock(self.directory / "runtime/writer.lock"):
            self.store.recover_no_retry()
            self.demo = StreamResearch(self.directory, paths=self.paths)
            await self.demo.start()
            await self.demo.stop()
        self.metrics = runtime.state().get("network", {})
        # Older versions could leave the periodic RUNNING sample after an abort.
        # Downgrade the retained view from verified audit; never restamp old DBs.
        if lifecycle and lifecycle[-1]["kind"] == "STREAM_ABORTED":
            self.metrics.update(
                last_error=lifecycle[-1]["details"]["error"],
                abort_reason=lifecycle[-1]["details"]["error"],
                finalization="BLOCKED",
                collection_state="ERROR",
            )
            if self.metrics["last_error"] == "STREAM_TIME_REVERSED":
                self.metrics.update(
                    timestamp_integrity="FAILED_EVENT_TIME_ORDER",
                    time_context=lifecycle[-1]["details"].get("time_context"),
                )
        self.flow_count = self.metrics.get("flow_records", 0)
        self.eligible = self.metrics.get("eligible_flows", 0)
        self.excluded = self.metrics.get("rejected_flows", 0)
        self.metrics.update(
            packets_per_second=None,
            flows_per_minute=None,
            eligible_flows_per_minute=None,
            capture_uptime_seconds=None,
            runtime_rss_bytes=None,
            runtime_cpu_seconds=None,
            current_inference_count=0,
            retained_inference_count=self.metrics.get("inference_count"),
            inference_count=0,
            inferences_per_minute=None,
            advisory_latency_seconds=None,
            retained_previous_active_flows=self.metrics.get("active_flows"),
            active_flows=0,
            retained_metadata_bytes=0,
            restart_gap=True,
        )
        self.state = "RETAINED_STREAM_NOT_LIVE"
        self.last_error = self.metrics.get("last_error")
        return self.snapshot()

    def snapshot(self):
        audit_valid = True
        try:
            if self.store is not None:
                self.store.runtime.verify_audit()
            research = (
                self.demo.snapshot()
                if self.demo
                else {
                    "records": [],
                    "model_metrics": {},
                    "audit_integrity": "NO_DATA",
                    "worker_running": False,
                }
            )
        except (ValueError, OSError, StorageError):
            audit_valid = False
            research = {
                "records": [],
                "model_metrics": {},
                "audit_integrity": "INVALID",
                "worker_running": None,
            }
        live = bool(
            not self.fixture
            and self.capture is not None
            and self.capture.is_live()
            and self.task is not None
            and not self.task.done()
            and not self.aborted
            and audit_valid
        )
        return dict(
            state=self.state if audit_valid else "UNKNOWN",
            collection_live=live,
            prepare_active=self.preparing or bool(self.task and not self.task.done()),
            listener_ready=bool(self.capture and self.capture.listener_ready()),
            capture_permission="FIXTURE_NO_CAPTURE"
            if self.fixture
            else "VERIFIED_TEMPORARY_CAPABILITY_DROP"
            if live
            else "USER_AUTHENTICATION_REQUIRED",
            session_id=str(self.session.session_id) if self.session else None,
            input_origin="FIXTURE"
            if self.fixture
            else "NATIVE_AF_PACKET"
            if self.session
            else "NO_DATA",
            network=dict(self.metrics),
            flow_eligibility=dict(
                eligible=self.eligible,
                rejected=self.excluded,
                pending=self.metrics.get("queue_backlog"),
            ),
            research=research,
            collectors={
                "network": "LIVE_COLLECTION"
                if live
                else "FIXTURE_NO_CAPTURE"
                if self.fixture
                else "STOPPED",
                "dns": "NOT_REQUESTED"
                if not self.policy.dns_headers
                else "LIVE_HEADERS_ONLY"
                if live
                else "FIXTURE_NO_CAPTURE"
                if self.fixture
                else "RETAINED_NOT_LIVE"
                if self.state == "RETAINED_STREAM_NOT_LIVE"
                else "STOPPED",
                "dns9_ai": "BLOCKED_PRODUCER_PARITY_UNVERIFIED",
            },
            last_error=self.last_error if audit_valid else "STREAM_AUDIT_OR_RECEIPT_INVALID",
            runtime_audit_integrity="VERIFIED" if self.store and audit_valid else "UNKNOWN",
            policy=self.policy.model_dump(mode="json"),
            operational_gate="OPERATIONAL_INFERENCE_BLOCKED",
            operational_input="NOT_INFERABLE",
            write_policy="WRITE_DENIED",
        )
