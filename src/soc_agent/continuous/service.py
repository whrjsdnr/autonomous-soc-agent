"""Independent collector task, durable bounded handoff and isolated analysis process.

This ordinary-user service never starts a privileged helper. Native installation
and sustained TCX authority are distinct, currently unactivated service contracts.
"""

import asyncio
import json
import os
import resource
import time
from pathlib import Path
from uuid import UUID, uuid4

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


class ContinuousRuntime:
    def __init__(self, directory: Path, *, source=None, analysis=None):
        self.directory = directory
        self.store = Store(directory)
        self.config = self.store.config
        self.source = source or ReplaySource(self.config)
        self.analysis = analysis or AnalysisService(directory / "analysis", self.config.ml_root)
        self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
        self.epoch = uuid4()
        self.last_sequence = 0
        self.last_event_ns = None
        self.done = asyncio.Event()
        self.stop = asyncio.Event()
        self.collector_state = "STOPPED"
        self.worker_state = "STOPPED"
        self.last_error = None
        self.circuit = False
        self.worker_failures = 0
        self.collector_failures = 0
        self.metrics = {
            k: 0
            for k in [
                "received",
                "packets",
                "dns_inputs",
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

        self.dns = IsolatedDNS(self.epoch)
        self.dns_window = None
        self.started = time.monotonic()

    def snapshot(self):
        analysis = self.analysis.snapshot()
        authentication = {"state": "NOT_ATTACHED", "events": None}
        if self.config.authentication_runtime:
            from soc_agent.linux_runtime.operator import status

            authentication = status(self.config.authentication_runtime)
        return dict(
            authentication=authentication,
            mode="CONTINUOUS",
            source=self.config.source,
            state="DEGRADED"
            if self.circuit or self.collector_state == "CIRCUIT_OPEN"
            else "RUNNING",
            service_pid=os.getpid(),
            collector=self.collector_state,
            worker=self.worker_state,
            collection_live=False,
            source_assurance="REPLAY_ONLY_NO_NATIVE_CAPTURE",
            heartbeat_unix=time.time(),
            uptime_seconds=time.monotonic() - self.started,
            clock_epoch=str(self.epoch),
            metrics=dict(self.metrics),
            queue=self.store.queue.counts(),
            circuit_open=self.circuit,
            last_error=self.last_error,
            analysis=analysis,
            recent_results=list(self.last_results),
            dns=self.dns.snapshot(),
            dns9="INCOMPLETE_TRAINING_EXTRACTION_CONTRACT",
            api="NOT_AUTOMATICALLY_AUTHORIZED",
            audit="VERIFIED",
            resources=dict(
                cpu_seconds=time.process_time(),
                peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            ),
            cleanup="PENDING_SERVICE_STOP",
        )

    async def publish(self):
        self.store.update(self.snapshot())

    async def handoff(self, job):
        self.metrics["flows"] += int(job.kind == "packet_window")
        if len(list((self.directory / "inputs").glob("*.json"))) >= self.config.max_windows:
            raise ValueError("CONTINUOUS_WINDOW_RETENTION_REQUIRES_ARCHIVAL")
        if job.kind == "packet_window":
            self.metrics["eligible" if job.quality == "ELIGIBLE" else "incomplete"] += 1
        try:
            self.store.enqueue(job)
        except QueueFull:
            self.metrics["queue_dropped"] += 1
            self.store.event(
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

    async def observe(self, raw):
        if (
            not isinstance(raw, dict)
            or type(raw.get("sequence")) is not int
            or raw["sequence"] != self.last_sequence + 1
        ):
            self.metrics["source_gaps"] += 1
            await self.complete(self.aggregator.close("RESTART_GAP"), self.last_event_ns or 0)
            self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
            raise ValueError("CONTINUOUS_SOURCE_SEQUENCE_GAP")
        self.last_sequence = raw["sequence"]
        self.metrics["received"] += 1
        identity = str(UUID(raw["id"]))
        kind = raw.get("kind")
        if kind not in ("packet", "job", "excluded"):
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
        if self.store.seen(
            identity, {key: value for key, value in raw.items() if key != "sequence"}
        ):
            self.metrics["duplicates"] += 1
            return
        if kind == "packet":
            packet = PacketObservation.model_validate(raw["packet"])
            if packet.timestamp_origin != "FIXTURE":
                raise ValueError("CONTINUOUS_REPLAY_CANNOT_ATTEST_NATIVE")
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

    async def collect(self):
        try:
            for attempt in range(self.config.collector_restarts + 1):
                self.last_sequence = 0
                self.last_event_ns = None
                self.collector_state = "RUNNING_REPLAY"
                try:
                    async for raw in self.source.events():
                        if self.stop.is_set():
                            break
                        await self.observe(raw)
                    self.collector_state = "STOPPED" if self.stop.is_set() else "EOF_NOT_LIVE"
                    break
                except (ValueError, OSError, RuntimeError) as error:
                    if self.last_error is None:
                        self.last_error = type(error).__name__ + ":" + str(error)
                    self.metrics["invalid"] += 1
                    self.collector_failures += 1
                    self.store.event(
                        "CONTINUOUS_COLLECTOR_FAILED",
                        dict(attempt=attempt, epoch=str(self.epoch), first_error=self.last_error),
                    )
                    await self.complete(
                        self.aggregator.close("RESTART_GAP"), self.last_event_ns or 0
                    )
                    self.aggregator = StreamingFlows(max_flows=self.config.max_active_flows)
                    self.epoch = uuid4()
                    if attempt == self.config.collector_restarts:
                        self.collector_state = "CIRCUIT_OPEN"
                        self.last_error = self.last_error or "CONTINUOUS_COLLECTOR_CIRCUIT_OPEN"
                        break
                    self.metrics["collector_restarts"] += 1
                    await asyncio.sleep(0.1)
            await self.complete(self.aggregator.close("SHUTDOWN"), self.last_event_ns or 0)
        finally:
            await self.source.close()
            self.done.set()

    async def consume(self):
        self.worker_state = "IDLE"
        while not self.stop.is_set():
            if self.circuit:
                self.worker_state = "CIRCUIT_OPEN"
                await asyncio.sleep(0.1)
                continue
            claim = self.store.queue.claim()
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
                await self.analysis.start(path)
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
                self.store.event(
                    "CONTINUOUS_ANALYSIS_COMPLETED",
                    dict(
                        event=str(claim.event.event_id),
                        output=value["output"],
                        incident=outcome["incident_id"],
                    ),
                )
                self.store.queue.finish(
                    claim,
                    dict(
                        inference="VERIFIED_OFFLINE",
                        incident_id=outcome["incident_id"],
                        workflow="COMPLETED",
                        human_boundary="WRITE_DENIED",
                    ),
                )
                self.worker_failures = 0
            except asyncio.CancelledError:
                self.store.queue.fail(claim, "WORKER_FAILURE")
                self.store.event(
                    "CONTINUOUS_WORKER_CANCELLED_UNKNOWN", dict(event=str(claim.event.event_id))
                )
                raise
            except (ValueError, OSError, RuntimeError):
                self.metrics["model_errors"] += 1
                self.worker_failures += 1
                self.store.queue.fail(claim, "WORKER_FAILURE")
                self.store.event(
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
            self.store.control()
            self.store.queue.recover()
            self.store.event(
                "CONTINUOUS_SERVICE_STARTED",
                dict(pid=os.getpid(), epoch=str(self.epoch), source=self.config.source),
            )
            collector = asyncio.create_task(self.collect())
            consumer = asyncio.create_task(self.consume())
            try:
                while not self.stop.is_set():
                    current = self.store.state()
                    if current["stop_requested"]:
                        self.stop.set()
                        break
                    if current["reset_worker"]:
                        self.circuit = False
                        self.worker_failures = 0
                        self.store.control()
                        self.store.event("CONTINUOUS_WORKER_RESET", {})
                    if consumer.done():
                        consumer.result()
                        raise ValueError("CONTINUOUS_WORKER_TASK_EXITED")
                    if collector.done():
                        collector.result()
                    size = sum(p.stat().st_size for p in self.directory.rglob("*") if p.is_file())
                    if size >= self.config.max_storage_bytes:
                        raise ValueError("CONTINUOUS_STORAGE_LIMIT_REQUIRES_ARCHIVAL")
                    await self.publish()
                    await asyncio.sleep(self.config.heartbeat_seconds)
            finally:
                self.stop.set()
                collector.cancel()
                await asyncio.gather(collector, return_exceptions=True)
                try:
                    await asyncio.wait_for(asyncio.shield(consumer), self.config.shutdown_seconds)
                except TimeoutError:
                    self.store.event("CONTINUOUS_DRAIN_DEADLINE", {})
                    consumer.cancel()
                    await asyncio.gather(consumer, return_exceptions=True)
                await self.source.close()
                flush_error = None
                try:
                    for event in self.dns.finish(aborted=True):
                        self.store.event("CONTINUOUS_DNS_TRANSACTION", event)
                    await self.complete(self.aggregator.close("SHUTDOWN"), self.last_event_ns or 0)
                except (ValueError, OSError, RuntimeError) as error:
                    # Evidence/storage failure must never skip owned process cleanup.
                    flush_error = type(error).__name__
                    self.last_error = self.last_error or "CONTINUOUS_FINAL_FLUSH_FAILED"
                try:
                    await self.analysis.close()
                except ValueError:
                    self.store.event("CONTINUOUS_CLEANUP_FAILED", {})
                    self.store.update(
                        self.snapshot() | dict(state="DEGRADED", cleanup="UNVERIFIED")
                    )
                    raise
                self.store.event(
                    "CONTINUOUS_SERVICE_STOPPED",
                    dict(
                        epoch=str(self.epoch),
                        metrics=dict(self.metrics),
                        first_error=self.last_error,
                        final_flush_error=flush_error,
                    ),
                )
                final = self.snapshot() | dict(
                    state="STOPPED",
                    collector="STOPPED",
                    worker="STOPPED",
                    cleanup="VERIFIED",
                    final_flush="FAILED" if flush_error else "VERIFIED",
                    collection_live=False,
                )
                self.store.update(final)
