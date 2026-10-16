"""Optional AF_PACKET companion inside the existing single-writer Linux Runtime."""

import asyncio
import json
import resource
import sqlite3
from collections import deque
from pathlib import Path
from time import monotonic
from uuid import uuid4

from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
    validate_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
    interface_identity,
)
from soc_agent.security_ai.operational.network_capture.models import (
    CaptureConfig,
    FlowSummary,
    PacketObservation,
    model_gates,
)
from soc_agent.security_ai.operational.network_capture.parsing import PacketRejected, parse_packet
from soc_agent.security_ai.operational.network_capture.pipeline import NetworkPipeline
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.state.evidence import utc_now


def configure(directory: Path, config: CaptureConfig):
    validate_directory(directory)
    with exclusive_runtime_lock(directory / "writer.lock"):
        store = RuntimeStore(directory)
        target = directory / "network"
        if target.exists() or target.is_symlink() or store.state().get("network_config_digest"):
            raise ValueError("NETWORK_RECONFIGURATION_REQUIRES_REVIEW")
        identity = interface_identity(config.interface)
        create_private_directory(target, exist_ok=False)
        EventQueue.create(target / "queue.sqlite")
        OperationalSourceStore.create(
            target / "sources.sqlite",
            allowed_lateness_seconds=60,
            max_future_skew_seconds=5,
            capacity=10000,
        )
        payload = {"config": config.model_dump(mode="json"), "interface_id": identity}
        path = target / "config.json"
        create_private_file(path)
        path.write_text(json.dumps(payload))
        digest = content_digest_payload(payload)
        store.event("NETWORK_CONFIGURED", {"config_digest": digest, "origin": config.origin})
        store.update(
            network_config_digest=digest,
            network={
                "state": "STOPPED",
                "readiness": "NOT_READY",
                "gates": model_gates(),
                "capture_drops": None,
                "packets_per_second": None,
                "dns_queries_per_minute": None,
                "flows_per_minute": None,
                "inference_count": 0,
                "inference_success": 0,
                "inference_failure": 0,
                "last_inference": None,
            },
        )


def configuration(directory: Path, store: RuntimeStore):
    path = directory / "network/config.json"
    state = store.state()
    if not state.get("network_config_digest"):
        if path.exists() or path.is_symlink():
            raise ValueError("UNCOMMITTED_NETWORK_CONFIGURATION")
        return None
    validate_directory(path.parent)
    validate_file(path)
    if path.stat().st_size > 8192:
        raise ValueError("NETWORK_CONFIGURATION_SIZE")
    payload = json.loads(path.read_text())
    if content_digest_payload(payload) != state["network_config_digest"]:
        raise ValueError("NETWORK_CONFIGURATION_DIGEST")
    config = CaptureConfig.model_validate(payload["config"])
    return config, payload["interface_id"]


class NetworkMonitor:
    def __init__(
        self,
        directory: Path,
        store: RuntimeStore,
        *,
        capture=None,
        flow_handler=None,
        generation=None,
    ):
        self.directory, self.store = directory, store
        saved = configuration(directory, store)
        if saved is None:
            raise ValueError("NETWORK_NOT_CONFIGURED")
        self.config, self.identity = saved
        self.capture = capture if capture is not None else PacketCapture(self.config)
        if self.capture.identity != self.identity:
            raise ValueError("NETWORK_INTERFACE_CHANGED_REQUIRES_REVIEW")
        self.pipeline = NetworkPipeline(
            EventQueue(directory / "network/queue.sqlite"),
            OperationalSourceStore(
                directory / "network/sources.sqlite",
                allowed_lateness_seconds=60,
                max_future_skew_seconds=5,
                capacity=10000,
            ),
            store.config.incident_id,
            self.config,
            self.identity,
            store,
        )
        self.generation = generation or str(uuid4())
        self.flow_handler = flow_handler
        self.sequence = 0
        self.stopped = asyncio.Event()
        self.metrics = {
            "state": "STARTING",
            "readiness": "NOT_READY",
            "packets_collected": 0,
            "packets_rejected": 0,
            "dns_queries": 0,
            "dns_parse_failures": 0,
            "capture_drops": None,
            "kernel_packets": None,
            "gap_count": store.state().get("network", {}).get("gap_count", 0) + 1,
            "packets_per_second": None,
            "dns_queries_per_minute": None,
            "flows_per_minute": None,
            "last_packet_timestamp": None,
            "last_error": None,
            "finalization": "PENDING",
            "gates": model_gates(),
            "inference_count": 0,
            "inference_success": 0,
            "inference_failure": 0,
            "last_inference": None,
            "finding_count": 0,
            "input_origin": self.config.origin,
            "capture_generation": self.generation,
            "packet_payload_stored": False,
            "dns_names_retained": self.config.retain_query_names,
        }
        self.since = monotonic()
        self.last_window = self.since
        self.last_packets = self.last_dns = self.last_flows = 0
        self.samples = deque([(self.since, 0, 0, 0)], maxlen=601)
        self._publish()

    def _step(self):
        state = self.pipeline.step()
        item = self.pipeline.last_committed
        if self.flow_handler is not None and item is not None:
            event, record, receipt = item
            if isinstance(record, FlowSummary) and event.source.generation == self.generation:
                self.flow_handler(event, record, receipt)
        return state

    def _publish(self):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        self.metrics["runtime_rss_peak_bytes"] = usage.ru_maxrss * 1024
        self.metrics["runtime_cpu_seconds"] = usage.ru_utime + usage.ru_stime
        if hasattr(self.capture, "extra_metrics"):
            self.metrics.update(self.capture.extra_metrics())
        self.metrics["flow_records"] = self.pipeline.generated_flows
        self.metrics["measured_at"] = utc_now().isoformat()
        counts = self.pipeline.queue.counts()
        self.metrics["queue_backlog"] = counts.get("PENDING", 0) + counts.get("CLAIMED", 0)
        self.metrics["queue_poison"] = counts.get("POISON", 0)
        self.store.update(network=self.metrics)

    def _sample(self):
        stats = self.capture.statistics()
        if stats is None:
            self.metrics["capture_drops"] = None
            self.metrics["kernel_packets"] = None
            raise CaptureUnavailable("CAPTURE_DROP_METRICS_UNKNOWN")
        self.metrics["kernel_packets"] = (self.metrics["kernel_packets"] or 0) + stats[0]
        self.metrics["capture_drops"] = (self.metrics["capture_drops"] or 0) + stats[1]
        if stats[1]:
            self.metrics["gap_count"] += 1
            raise CaptureUnavailable("CAPTURE_DROP_DETECTED")
        flows = self.pipeline.generated_flows
        now = monotonic()
        self.samples.append(
            (now, self.metrics["packets_collected"], self.metrics["dns_queries"], flows)
        )
        while len(self.samples) > 2 and self.samples[1][0] < now - 60:
            self.samples.popleft()
        first, packets, dns, old_flows = self.samples[0]
        duration = max(0.001, now - first)
        self.metrics.update(
            packets_per_second=(self.metrics["packets_collected"] - packets) / duration,
            dns_queries_per_minute=60 * (self.metrics["dns_queries"] - dns) / duration,
            flows_per_minute=60 * (flows - old_flows) / duration,
            rate_window_seconds=duration,
            flow_records=flows,
        )

    async def run(self):
        opened = False
        try:
            self.pipeline.recover()
            self.store.event(
                "NETWORK_CAPTURE_GAP",
                {
                    "reason": "NO_KERNEL_PACKET_REPLAY_ON_START_OR_RESTART",
                    "generation": self.generation,
                    "origin": self.config.origin,
                },
            )
            for _ in range(256):
                if self._step() == "IDLE":
                    break
            self.capture.open()
            opened = True
            self.metrics.update(state="RUNNING", readiness="COLLECTING_DIAGNOSTIC_ONLY")
            while not self.stopped.is_set():
                for _ in range(64):
                    if self._step() == "IDLE":
                        break
                for _ in range(self.config.packet_batch):
                    if self.stopped.is_set():
                        break
                    # Do not read a packet that cannot be durably admitted.
                    if self.metrics.get("queue_backlog", 0) >= self.pipeline.queue.capacity - 2:
                        raise QueueFull("NETWORK_BACKPRESSURE")
                    value = self.capture.receive()
                    if value is None:
                        break
                    self.metrics["packets_collected"] += 1
                    self.sequence += 1
                    try:
                        if isinstance(value, PacketObservation):
                            packet = PacketObservation.model_validate(value.model_dump())
                            if (
                                packet.interface_id != self.identity
                                or self.config.origin != "NATIVE_AF_PACKET"
                            ):
                                raise CaptureUnavailable("HELPER_METADATA_SOURCE_MISMATCH")
                        else:
                            frame, stamp, direction, *native_time = value
                            packet = parse_packet(
                                frame,
                                interface_id=self.identity,
                                timestamp=stamp,
                                direction=direction,
                                native=self.config.origin == "NATIVE_AF_PACKET",
                                retain_name=self.config.retain_query_names,
                                capture_timestamp_ns=native_time[0] if native_time else None,
                            )
                    except PacketRejected:
                        self.metrics["packets_rejected"] += 1
                        continue
                    self.pipeline.packet(packet, self.generation, self.sequence)
                    self.metrics["last_packet_timestamp"] = packet.timestamp.isoformat()
                    if packet.dns and not packet.dns.response:
                        self.metrics["dns_queries"] += 1
                    if packet.dns_status.startswith("DNS_") and packet.dns_status != "DNS_PARSED":
                        self.metrics["dns_parse_failures"] += 1
                now = utc_now()
                if hasattr(self.capture, "flow_watermark"):
                    now = self.capture.flow_watermark(now)
                self.pipeline.flush(now)
                for _ in range(64):
                    if self._step() == "IDLE":
                        break
                self._sample()
                self._publish()
                await asyncio.sleep(0.1)
        except (ValueError, OSError, StorageError, sqlite3.Error) as error:
            code = (
                str(error)
                if isinstance(error, (CaptureUnavailable, PacketRejected))
                else type(error).__name__
            )
            self.metrics.update(
                state="DEGRADED", readiness="NOT_READY", last_error=code, finalization="BLOCKED"
            )
            cause = error.__cause__
            self.metrics["storage_error_code"] = (
                getattr(cause, "sqlite_errorname", "UNKNOWN")
                if isinstance(error, StorageError)
                else None
            )
            if opened:
                self.metrics["gap_count"] += 1
                if code != "CAPTURE_DROP_DETECTED":
                    self.metrics["capture_drops"] = None
            self.store.event(
                "NETWORK_COLLECTION_BLOCKED",
                {"reason": code, "storage_error_code": self.metrics["storage_error_code"]},
            )
        finally:
            try:
                if opened and self.metrics["state"] == "RUNNING":
                    verified = (
                        hasattr(self.capture, "completion_verified")
                        and not self.capture.closed.is_set()
                        and self.capture.completion_verified()
                    )
                    if verified:
                        self._sample()
                    self.pipeline.flush(utc_now(), "SHUTDOWN")
                    for _ in range(self.pipeline.queue.capacity + 1):
                        if self._step() == "IDLE":
                            break
                    else:
                        raise QueueFull("NETWORK_FINALIZATION_BACKPRESSURE")
                    if verified:
                        self._verify_finalization()
                        self.metrics["finalization"] = "VERIFIED"
                        self.store.event(
                            "NETWORK_CAPTURE_FINALIZED",
                            {
                                "generation": self.generation,
                                "packets": self.metrics["packets_collected"],
                                "flows": self.pipeline.generated_flows,
                                "research": "ELIGIBLE_TIMEOUT_FLOWS_ONLY",
                            },
                        )
                    else:
                        self.metrics["finalization"] = "NOT_APPROVED_STOP_OR_MISSING_COUNTERS"
                    self.metrics.update(state="STOPPED", readiness="NOT_READY")
            except (ValueError, OSError, StorageError, sqlite3.Error):
                self.metrics.update(
                    state="DEGRADED",
                    readiness="NOT_READY",
                    last_error="NETWORK_SHUTDOWN_INCOMPLETE",
                    finalization="BLOCKED",
                )
            finally:
                if hasattr(self.capture, "completion_verified"):
                    self.capture.close(
                        reason="PERSISTENCE_OR_FINALIZATION_FAILED"
                        if self.metrics["last_error"]
                        else "CAPTURE_FINALIZED"
                        if self.metrics["finalization"] == "VERIFIED"
                        else "EXPLICIT_STOP_BEFORE_PERSISTENCE"
                    )
                else:
                    self.capture.close()
                self._publish()

    def _verify_finalization(self):
        if not self.capture.completion_verified() or self.metrics["capture_drops"] != 0:
            raise CaptureUnavailable("NETWORK_FINAL_COUNTER_OR_TRANSPORT_MISMATCH")
        counts = self.pipeline.queue.counts()
        if any(counts.get(k, 0) for k in ("PENDING", "CLAIMED", "POISON")):
            raise ValueError("NETWORK_FINAL_QUEUE_NOT_COMMITTED")
        with self.pipeline.queue.database.transaction(write=False) as c:
            packets = c.execute(
                "SELECT count(*) FROM realtime_events WHERE status='DONE' "
                "AND json_extract(payload,'$.source.generation')=? "
                "AND json_extract(payload,'$.metadata.code')='packet'",
                (self.generation,),
            ).fetchone()[0]
        if packets != self.capture.delivered or packets != self.metrics["packets_collected"]:
            raise ValueError("NETWORK_FINAL_PERSISTENCE_COUNT_MISMATCH")
        self.store.verify_audit()


def network_status(directory: Path, store: RuntimeStore):
    configured = configuration(directory, store)
    if configured is None:
        return {
            "state": "DISABLED",
            "readiness": "NOT_READY",
            "packets_per_second": None,
            "dns_queries_per_minute": None,
            "flows_per_minute": None,
            "capture_drops": None,
            "inference_count": None,
            "gates": model_gates(),
        }
    value = dict(store.state().get("network", {}))
    # A stale persisted RUNNING flag is not live readiness.
    from datetime import datetime

    stamp = value.get("measured_at")
    if value.get("state") == "RUNNING" and (
        not stamp or not 0 <= (utc_now() - datetime.fromisoformat(stamp)).total_seconds() <= 5
    ):
        value.update(state="UNKNOWN", readiness="NOT_READY", last_error="CAPTURE_HEARTBEAT_STALE")
    if value.get("state") != "RUNNING":
        # Persisted last-window rates are history, not current live measurements.
        for key in ("packets_per_second", "dns_queries_per_minute", "flows_per_minute"):
            value[key] = None
    return value
