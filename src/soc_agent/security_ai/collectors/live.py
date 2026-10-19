"""Explicit manual Native attachment, bounded streaming, independent diagnostics gate.

A process that is reading packets is not a verified model input. Until Zeek exposes
an unambiguous capture-statistics failure signal, Native AI remains BLOCKED.
The identical stream reader can be verified against a full offline PCAP reference.
"""

import asyncio
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.collectors.live_contract import LivePlan, command, new_plan, verify
from soc_agent.security_ai.collectors.live_process import (
    StreamProcess,
    process_identity,
    same_process,
)
from soc_agent.security_ai.collectors.live_stream import Stream, decode
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.offline import OfflineZeek, file_digest, pcap_digest
from soc_agent.security_ai.collectors.reader import LogReader
from soc_agent.security_ai.collectors.store import CollectorStore
from soc_agent.security_ai.collectors.zeek import ZeekCollector
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.service import write_new


class LiveZeekCollector(ZeekCollector):
    def __init__(self, directory: Path, *, paths=None):
        super().__init__(directory, packet_mode=True, paths=paths)
        self.root = directory.absolute() / "zeek-live-collector"
        self.state = "IDLE"
        self.plan = self.stream = self.process_runner = None
        self.process_task = None
        self.fixture = False
        self.watch_started = None
        self.result = None
        self.audit_failed = False

    async def prepare(self, *, pcap: Path | None = None, sha256: str | None = None):
        if self.preparing or self.task is not None and not self.task.done():
            raise ValueError("ZEEK_ALREADY_ACTIVE_OR_PREPARING")
        self.preparing = True
        self.state = "PREPARING"
        try:
            self._release()
            await asyncio.to_thread(OfflineZeek().environment)
            self.plan = new_plan()
            self.fixture = pcap is not None
            if self.fixture:
                from soc_agent.security_ai.collectors.packet_input import reference

                if await asyncio.to_thread(pcap_digest, pcap) != sha256:
                    raise ValueError("ZEEK_PCAP_DIGEST_MISMATCH")
                await asyncio.to_thread(reference, pcap)
                self.pcap, self.sha256 = pcap, sha256
            elif sha256 is not None:
                raise ValueError("ZEEK_NATIVE_NO_PCAP_LABEL")
            create_private_directory(self.root)
            if len(list(self.root.glob("session-*"))) >= 8:
                raise ValueError("ZEEK_SESSION_RETENTION_REVIEW_REQUIRED")
            self.directory = self.root / ("session-" + self.plan.session_id.hex)
            create_private_directory(self.directory)
            create_private_directory(self.directory / "logs")
            self.writer = exclusive_runtime_lock(self.directory / "writer.lock")
            self.writer.__enter__()
            source = Source(
                session_id=self.plan.session_id,
                source_digest=sha256 if self.fixture else self.plan.identity,
                origin="ZEEK_OFFLINE_PCAP" if self.fixture else "ZEEK_NATIVE_LIVE",
                capture_integrity="OFFLINE_FILE_DIGEST_VERIFIED" if self.fixture else "UNVERIFIED",
            )
            self.store = CollectorStore(self.directory, source)
            self.stream = Stream(source)
            write_new(self.directory / "plan.json", self.plan.model_dump(mode="json"))
            write_new(self.directory / "controller.json", process_identity(os.getpid()))
            self.store.runtime.event(
                "ZEEK_LIVE_PLAN_PREPARED",
                dict(
                    plan_digest=self.plan.identity,
                    bundle_digest=self.plan.bundle_digest,
                    origin=source.origin,
                    interface=self.plan.interface,
                    authentication="USER_TERMINAL_ONLY",
                    native_inference="BLOCKED",
                ),
            )
            self.stop_requested = False
            self.producer = self.result = self.process_runner = None
            self.queue_depth = self.queue_peak = self.rows_read = self.duplicates = 0
            self.last_error = None
            self.recovery_state = "NOT_ATTEMPTED"
            self.audit_failed = False
            self.state = "STARTING" if self.fixture else "AUTHENTICATION_REQUIRED"
            return self.snapshot()
        except (OSError, ValueError, sqlite3.Error):
            self.state, self.last_error = "ERROR", "ZEEK_LIVE_PREPARATION_FAILED"
            self._release()
            raise
        finally:
            self.preparing = False

    async def start(self):
        if self.state not in {"AUTHENTICATION_REQUIRED", "STARTING"}:
            raise ValueError("ZEEK_NOT_PREPARED")
        self.watch_started = time.monotonic()
        if self.fixture:
            self.process_runner = StreamProcess(self.directory, self.plan, fixture=self.pcap)
            self.process_task = asyncio.create_task(asyncio.to_thread(self.process_runner.run))
        # Native start watches only. It never runs sudo, Docker or a capture process.
        self.task = asyncio.create_task(self._watch())
        return self.snapshot()

    def _process(self):
        path = self.directory / "process.json"
        if not path.exists():
            return None
        value = json.loads(read_local(path, 8192))
        if (
            value.get("plan_digest") != self.plan.identity
            or value.get("image") != self.plan.image
            or value.get("native_capture") != (not self.fixture)
        ):
            raise ValueError("ZEEK_PROCESS_IDENTITY_MISMATCH")
        return value

    def _poll(self, reader):
        rows, cursor = reader.read(32)
        if not rows:
            return False
        self.queue_depth = len(rows)
        self.queue_peak = max(self.queue_peak, self.queue_depth)
        events = {"network": [], "dns": []}
        packet_path = self.directory / "logs/network14_packets.log"
        if not packet_path.exists():
            create_private_file(packet_path)
        with packet_path.open("ab") as packets:
            for raw in rows:
                envelope = decode(raw)
                event = self.stream.accept(envelope)
                if envelope.kind == "packet":
                    packets.write(json.dumps(envelope.data).encode() + b"\n")
                if event:
                    events[event.kind].append(event)
        for kind, values in events.items():
            added, duplicates = self.store.commit(kind, values, cursor)
            self.rows_read += added
            self.duplicates += duplicates
        self.store.runtime.event(
            "ZEEK_STREAM_PROGRESS",
            dict(
                sequence=self.stream.sequence,
                packets=self.stream.packet_count,
                cursor=cursor,
                closed=self.stream.closed,
            ),
        )
        self.queue_depth = 0
        self._budget()
        return True

    async def _watch(self):
        reader = LogReader(self.directory / "stream.jsonl")
        try:
            while True:
                verify(self.plan, self.plan.identity)
                failure = self.directory / "launch-failure.json"
                if failure.exists():
                    reason = json.loads(read_local(failure, 8192))
                    if reason.get("plan_digest") != self.plan.identity:
                        raise ValueError("ZEEK_AUTH_FAILURE_IDENTITY_INVALID")
                    raise ValueError(reason.get("error", "ZEEK_AUTHENTICATION_FAILED"))
                process = self._process()
                if (
                    self.process_task
                    and self.process_task.done()
                    and not (self.directory / "exit.json").exists()
                ):
                    await self.process_task
                    raise ValueError("ZEEK_PROCESS_EXIT_UNRECORDED")
                if process:
                    if self.started is None:
                        self.started = time.monotonic()
                    await asyncio.to_thread(self._poll, reader)
                    if self.stream.ready:
                        self.state = (
                            "ERROR"
                            if self.last_error
                            else "STOPPING"
                            if self.stop_requested
                            else "ACTIVE"
                            if self.fixture
                            else "DEGRADED"
                        )
                if (self.directory / "exit.json").exists():
                    # Process exit is not EOF: consume every bounded batch before finalizing.
                    while await asyncio.to_thread(self._poll, reader):
                        await asyncio.sleep(0)
                    reader.finish()
                    result = json.loads(read_local(self.directory / "exit.json", 8192))
                    if (
                        result.get("plan_digest") != self.plan.identity
                        or result.get("stream_sha256")
                        != file_digest(self.directory / "stream.jsonl")
                        or result.get("sequence") != self.stream.sequence
                        or not self.stream.closed
                        or not result.get("cleanup_verified")
                        or result.get("error")
                        or result.get("exit_code") not in {0, 124}
                    ):
                        raise ValueError("ZEEK_CLOSED_OR_PROCESS_INTEGRITY_UNVERIFIED")
                    self.result = result
                    self.store.runtime.event("ZEEK_STREAM_PROCESS_COMPLETED", result)
                    if self.fixture and not self.stop_requested:
                        from soc_agent.security_ai.collectors.producer_service import (
                            ProducerService,
                        )

                        self.producer = ProducerService(self, paths=self.paths)
                        await self.producer.produce(
                            dict(
                                packet_mode=True,
                                packet_policy_sha256=file_digest(
                                    Path(__file__).with_name("network14.zeek")
                                ),
                                log_sha256={
                                    "network14_packets.log": file_digest(
                                        self.directory / "logs/network14_packets.log"
                                    )
                                },
                            )
                        )
                        self.last_error = self.producer.last_error
                    self.state = "ERROR" if self.last_error else "STOPPED"
                    self.store.runtime.event(
                        "ZEEK_LIVE_FINALIZED",
                        dict(
                            finalization="PROCESS_ONLY_NATIVE_AI_BLOCKED"
                            if not self.fixture
                            else "PCAP_REFERENCE",
                            packet_count=self.stream.packet_count,
                            queue_final=0,
                            operational_gate="BLOCKED",
                            write_policy="WRITE_DENIED",
                        ),
                    )
                    break
                if self.stop_requested and not process:
                    self.state = "STOPPED"
                    break
                if process and not same_process(process["launcher"]):
                    raise ValueError("ZEEK_LAUNCHER_EXIT_WITHOUT_CLOSED")
                if time.monotonic() - self.watch_started > self.plan.duration_seconds + 20:
                    raise ValueError("ZEEK_AUTH_OR_CAPTURE_DEADLINE_EXCEEDED")
                await asyncio.sleep(0.05)
        except (OSError, ValueError, sqlite3.Error) as error:
            code = str(error)
            self.last_error = (
                code
                if re.fullmatch(r"ZEEK_[A-Z0-9_]{1,110}", code)
                else "ZEEK_LIVE_INTEGRITY_FAILED"
            )
            self.state = "ERROR"
            try:
                self._request_stop()
            except OSError:
                self.last_error = "ZEEK_STOP_SIGNAL_PERSISTENCE_FAILED"
            try:
                self.store.runtime.event(
                    "ZEEK_LIVE_ABORT", dict(error=self.last_error, inference_allowed=False)
                )
            except (OSError, ValueError, sqlite3.Error):
                self.audit_failed = True
                self.recovery_state = "BLOCKED_AUDIT_PERSISTENCE_FAILED"
                self.last_error = "ZEEK_AUDIT_PERSISTENCE_FAILED"
        finally:
            reader.close()
            if self.process_task is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(self.process_task), 10)
                except (ValueError, OSError, TimeoutError):
                    self.state, self.last_error = (
                        "ERROR",
                        self.last_error or "ZEEK_PROCESS_STOP_UNVERIFIED",
                    )
            self._release()

    def _request_stop(self):
        self.stop_requested = True
        if self.process_runner:
            self.process_runner.stop()
        if self.directory and not (self.directory / "stop.request").exists():
            create_private_file(self.directory / "stop.request")

    async def stop(self):
        self._request_stop()
        if self.producer:
            await self.producer.demo.stop()
        if self.task and not self.task.done():
            self.state = "STOPPING"
            try:
                await asyncio.wait_for(asyncio.shield(self.task), 15)
            except TimeoutError:
                self.state, self.last_error = "ERROR", "ZEEK_STOP_DEADLINE_UNVERIFIED"
        if self.producer:
            await self.producer.demo.stop()
        if self.state not in {"ERROR", "STOPPED"}:
            self.state = "STOPPED"
        self._release()
        return self.snapshot()

    async def recover(self):
        if self.task and not self.task.done():
            raise ValueError("ZEEK_ALREADY_ACTIVE")
        candidates = sorted(self.root.glob("session-*"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            return self.snapshot()
        self.directory = candidates[-1]
        self.plan = LivePlan.model_validate_json(read_local(self.directory / "plan.json", 8192))
        self.store = CollectorStore(self.directory)
        self.fixture = self.store.source.origin == "ZEEK_OFFLINE_PCAP"
        self.state = "ERROR"
        self.recovery_state = "BLOCKED_NO_AUTOMATIC_RESTART"
        with self.store.runtime.database.transaction(write=False) as db:
            completed = [
                json.loads(r[0])["details"]
                for r in db.execute(
                    "SELECT payload FROM monitor_audit "
                    "WHERE json_extract(payload,'$.kind')='ZEEK_STREAM_PROCESS_COMPLETED'"
                )
            ]
        if len(completed) != 1 or completed[0]["stream_sha256"] != file_digest(
            self.directory / "stream.jsonl"
        ):
            self.last_error = "ZEEK_RECOVERY_COMPLETION_UNVERIFIED"
            return self.snapshot()
        self.result = completed[0]
        if self.fixture and (self.directory / "producer-proof.json").exists():
            from soc_agent.security_ai.collectors.producer_service import ProducerService

            self.producer = ProducerService(self, paths=self.paths)
            await self.producer.recover()
        self.state, self.recovery_state = "STOPPED", "RESTORED_NO_CAPTURE_OR_INFERENCE_RESTART"
        return self.snapshot()

    def snapshot(self):
        # Reuse event/audit/receipt projections and bounded chart schema.
        value = super().snapshot()
        alive = False
        if self.plan and self.directory:
            process = self._process()
            alive = bool(
                process
                and same_process(process["launcher"])
                and not (self.directory / "exit.json").exists()
            )
        running = self.state in {"ACTIVE", "DEGRADED"} and alive
        value.update(
            state=self.state,
            collection_live=running and not self.fixture,
            listener_ready=False,
            input_origin=self.store.source.origin if self.store else "NO_DATA",
        )
        value["collectors"].update(network=self.state, dns=self.state)
        value["collector"].update(
            type="zeek-live",
            health=self.state,
            interface="lo",
            capture_integrity="OFFLINE_REFERENCE_ONLY"
            if self.fixture
            else "UNVERIFIED_PCAP_STATS_FAILURE_SIGNAL",
            approval=dict(
                state="USER_TERMINAL_REQUIRED"
                if self.state == "AUTHENTICATION_REQUIRED"
                else "NOT_AUTHORITY",
                plan_digest=self.plan.identity if self.plan else None,
            ),
            metrics={
                **value["collector"]["metrics"],
                "log_lag_seconds": None,
                "queue_capacity": 32,
                "process_alive": alive,
            },
        )
        value["network"].update(
            collector_network_events=self.store.counts().get("network", 0) if self.store else None,
            collector_dns_events=self.store.counts().get("dns", 0) if self.store else None,
            packet_metadata_count=self.stream.packet_count if self.stream else None,
            finalized_flows=len(self.stream.finalized) if self.stream else None,
            capture_interface="lo",
            capture_integrity="UNVERIFIED" if not self.fixture else "OFFLINE_FILE_DIGEST_VERIFIED",
            integrity_state="DEGRADED_NATIVE_MODELS_BLOCKED"
            if not self.fixture
            else "OFFLINE_REFERENCE",
            finalization=(
                "PCAP_REFERENCE_FINALIZED"
                if self.fixture
                else "PROCESS_VERIFIED_CAPTURE_UNVERIFIED"
            )
            if self.result
            else "NOT_FINALIZED",
            capture_uptime_seconds=time.monotonic() - self.started
            if self.started and running
            else None,
            capture_drops=self.stream.counters.get("pkts_dropped")
            if self.stream and self.stream.counters
            else None,
            gap_count=None,
            recovery_state=self.recovery_state,
        )
        value["collector_command"] = (
            command(self.directory, self.plan)
            if self.plan and self.state == "AUTHENTICATION_REQUIRED" and not self.fixture
            else None
        )
        if not self.fixture:
            for model in value["research"]["model_metrics"].values():
                model["reason"] = "ZEEK_NATIVE_CAPTURE_INTEGRITY_UNVERIFIED"
        if self.audit_failed:
            value["runtime_audit_integrity"] = "UNVERIFIED_ABORT_NOT_PERSISTED"
        value["last_error"] = self.last_error
        return value
