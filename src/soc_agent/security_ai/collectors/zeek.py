"""Experimental offline collection; owns no privilege or model worker."""

import asyncio
import json
import sqlite3
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.collectors.adapter import parse_line
from soc_agent.security_ai.collectors.models import Source
from soc_agent.security_ai.collectors.offline import VERSION, OfflineZeek
from soc_agent.security_ai.collectors.parity import report
from soc_agent.security_ai.collectors.reader import LogReader
from soc_agent.security_ai.collectors.store import CollectorStore


class ZeekCollector:
    def __init__(self, directory: Path, *, runner=None):
        self.root = directory.absolute() / "zeek-collector"
        self._injected_runner = runner is not None
        self.preparing = False
        self.runner = runner or OfflineZeek()
        self.task = None
        self.store = None
        self.state = "STOPPED"
        self.last_error = None
        self.readers = {}
        self.queue_peak = self.duplicates = self.rows_read = self.out_of_order = 0
        self.queue_depth = 0
        self.last_event_ns = None
        self.log_to_adapter_ms = None
        self.started = None
        self.writer = None
        self.directory = None
        self.recovery_state = "NOT_ATTEMPTED"

    def _release(self):
        for reader in self.readers.values():
            reader.close()
        self.readers.clear()
        if self.writer is not None:
            self.writer.__exit__(None, None, None)
            self.writer = None

    async def prepare(self, *, pcap: Path, sha256: str, mode="offline") -> dict:
        if self.preparing:
            raise ValueError("ZEEK_ALREADY_PREPARING")
        self.preparing = True
        try:
            return await self._prepare(pcap=pcap, sha256=sha256, mode=mode)
        finally:
            self.preparing = False

    async def _prepare(self, *, pcap: Path, sha256: str, mode="offline") -> dict:
        if mode != "offline":
            raise ValueError("ZEEK_LIVE_SEPARATE_APPROVAL_REQUIRED")
        if self.task is not None and not self.task.done():
            raise ValueError("ZEEK_ALREADY_ACTIVE")
        self._release()
        if not self._injected_runner:
            self.runner = OfflineZeek()
        await asyncio.to_thread(self.runner.environment)
        from soc_agent.security_ai.collectors.offline import pcap_digest

        if await asyncio.to_thread(pcap_digest, pcap) != sha256:
            raise ValueError("ZEEK_PCAP_DIGEST_MISMATCH")
        create_private_directory(self.root)
        if len(list(self.root.glob("session-*"))) >= 8:
            raise ValueError("ZEEK_SESSION_RETENTION_REVIEW_REQUIRED")
        self.directory = self.root / ("session-" + uuid4().hex)
        create_private_directory(self.directory)
        create_private_directory(self.directory / "logs")
        source = Source(
            session_id=uuid4(),
            source_digest=sha256,
            origin="ZEEK_OFFLINE_PCAP",
            version=VERSION,
            capture_integrity="OFFLINE_FILE_DIGEST_VERIFIED",
        )
        self.writer = exclusive_runtime_lock(self.directory / "writer.lock")
        self.writer.__enter__()
        try:
            self.store = CollectorStore(self.directory, source)
        except (OSError, ValueError):
            self._release()
            raise
        self.pcap, self.sha256 = pcap, sha256
        self.state, self.last_error = "READY_OFFLINE", None
        self.queue_peak = self.duplicates = self.rows_read = self.out_of_order = 0
        self.last_event_ns = None
        self.started = None
        return self.snapshot()

    async def start(self) -> dict:
        if self.state != "READY_OFFLINE":
            raise ValueError("ZEEK_NOT_PREPARED")
        self.started = time.monotonic()
        self.state = "OFFLINE_PROCESSING"
        self.task = asyncio.create_task(self._run())
        return self.snapshot()

    async def _run(self):
        try:
            result = await asyncio.to_thread(
                self.runner.run, self.pcap, self.sha256, self.directory / "logs"
            )
            self.store.runtime.event("ZEEK_OFFLINE_PROCESS_EXIT", result)
            await self._ingest()
            self.store.verify()
            self.state = "STOPPED"
            self.store.runtime.event(
                "COLLECTOR_COMPLETED",
                dict(
                    rows_read=self.rows_read,
                    duplicates=self.duplicates,
                    queue_final=0,
                    inference_count=0,
                ),
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            StorageError,
            sqlite3.Error,
            subprocess.SubprocessError,
        ) as error:
            self.state = "ERROR"
            self.recovery_state = "BLOCKED"
            code = str(error)
            self.last_error = (
                code
                if code.startswith("ZEEK_") and len(code) <= 128 and code.replace("_", "").isalnum()
                else "ZEEK_COLLECTOR_PROCESS_OR_STORAGE_FAILED"
            )
            if self.store is not None:
                self.store.runtime.event(
                    "COLLECTOR_FAILED",
                    dict(error=self.last_error, automatic_retry=False, inference_count=0),
                )
        finally:
            self._release()

    async def _ingest(self):
        from soc_agent.security_ai.collectors.offline import file_digest

        with self.store.runtime.database.transaction(write=False) as c:
            records = [
                json.loads(r[0])["details"]
                for r in c.execute(
                    "SELECT payload FROM monitor_audit "
                    "WHERE json_extract(payload,'$.kind')='ZEEK_OFFLINE_PROCESS_EXIT'"
                )
            ]
        if len(records) != 1 or set(records[0].get("log_sha256", {})) != {"conn.log", "dns.log"}:
            raise ValueError("ZEEK_OUTPUT_MANIFEST_MISSING")
        for name, sha in records[0]["log_sha256"].items():
            if (
                name not in {"conn.log", "dns.log"}
                or file_digest(self.directory / "logs" / name) != sha
            ):
                raise ValueError("ZEEK_OUTPUT_DIGEST_MISMATCH")
        for kind, name in [("network", "conn.log"), ("dns", "dns.log")]:
            reader = LogReader(self.directory / "logs" / name, self.store.cursor(kind))
            self.readers[kind] = reader
            while True:
                self._budget()
                lines, cursor = await asyncio.to_thread(reader.read, 32)
                if not lines:
                    reader.finish()
                    break
                if len(lines) > 32:
                    raise ValueError("ZEEK_INGESTION_QUEUE_OVERFLOW")
                self.queue_depth = len(lines)
                self.queue_peak = max(self.queue_peak, len(lines))
                before = time.monotonic()
                events = [parse_line(line, kind, self.store.source) for line in lines]
                for e in events:
                    if self.last_event_ns is not None and e.event_ns < self.last_event_ns:
                        self.out_of_order += 1
                    self.last_event_ns = e.event_ns
                _, duplicates = await asyncio.to_thread(self.store.commit, kind, events, cursor)
                self.queue_depth = 0
                self.duplicates += duplicates
                self.rows_read += len(lines)
                self.log_to_adapter_ms = (time.monotonic() - before) * 1000
                await asyncio.sleep(0)

    def _budget(self):
        if sum(p.stat().st_size for p in self.directory.rglob("*") if p.is_file()) > 64 * 1024**2:
            raise ValueError("ZEEK_SESSION_DISK_BUDGET_EXCEEDED")

    async def stop(self) -> dict:
        if self.task is not None and not self.task.done():
            await asyncio.to_thread(self.runner.stop)
            await asyncio.wait_for(asyncio.shield(self.task), 15)
        self._release()
        if self.state == "READY_OFFLINE":
            self.state = "STOPPED"
        return self.snapshot()

    def health(self) -> dict:
        return dict(state=self.state, last_error=self.last_error, live=False, experimental=True)

    def network_events(self):
        return self.store.events("network") if self.store else []

    def dns_events(self):
        return self.store.events("dns") if self.store else []

    def metrics(self) -> dict:
        counts = self.store.counts() if self.store else {}
        return dict(
            network_events=counts.get("network", 0) if self.store else None,
            dns_events=counts.get("dns", 0) if self.store else None,
            queue_depth=self.queue_depth,
            queue_capacity=32,
            backpressure="HIGH" if self.queue_depth >= 24 else "NORMAL",
            queue_peak=self.queue_peak,
            rows_read=self.rows_read,
            duplicates=self.duplicates,
            out_of_order_start_times=self.out_of_order,
            log_to_adapter_ms=self.log_to_adapter_ms,
            capture_to_log_ms=None,
            feature_generation_ms=None,
            inference_latency_ms=None,
            investigation_latency_ms=None,
            log_lag_seconds=None,
            inference_count=0,
        )

    def snapshot(self) -> dict:
        integrity = "NO_DATA"
        if self.store:
            try:
                self.store.verify()
                integrity = "VERIFIED"
            except (OSError, ValueError, StorageError, sqlite3.Error):
                integrity = "INVALID"
                self.state, self.last_error = "UNKNOWN", "ZEEK_AUDIT_OR_CHECKPOINT_INVALID"
        metrics = self.metrics()
        origin = self.store.source.origin if self.store else "NO_DATA"
        return dict(
            state=self.state,
            collection_live=False,
            listener_ready=False,
            session_id=str(self.store.source.session_id) if self.store else None,
            input_origin=origin,
            last_error=self.last_error,
            collector=dict(
                type="zeek",
                health=self.health(),
                metrics=metrics,
                parity=report(),
                version=VERSION,
                source_digest=self.store.source.source_digest if self.store else None,
                events=self.store.events() if self.store and integrity == "VERIFIED" else [],
            ),
            collectors=dict(
                network=self.state
                if self.state in {"ERROR", "UNKNOWN"}
                else "ZEEK_OFFLINE_DIAGNOSTIC"
                if self.store
                else "STOPPED",
                dns=self.state
                if self.state in {"ERROR", "UNKNOWN"}
                else "ZEEK_OFFLINE_DIAGNOSTIC"
                if self.store
                else "STOPPED",
                dns9_ai="BLOCKED_PRODUCER_PARITY_UNVERIFIED",
            ),
            network=dict(
                collector_network_events=metrics["network_events"],
                collector_dns_events=metrics["dns_events"],
                queue_backlog=metrics["queue_depth"],
                capture_drops=None,
                gap_count=None,
                finalization="DIAGNOSTICS_ONLY",
                recovery_state=self.recovery_state,
            ),
            research=dict(
                records=[],
                worker_running=False,
                model_metrics={
                    k: dict(state="BLOCKED", successful=0, reason="ZEEK_NETWORK14_PARITY_BLOCKED")
                    for k in ["quality", "edge"]
                },
            ),
            runtime_audit_integrity=integrity,
            operational_gate="OPERATIONAL_INFERENCE_BLOCKED",
            write_policy="WRITE_DENIED",
            observation_started_ns=time.monotonic_ns(),
        )

    async def recover(self) -> dict:
        if self.task is not None and not self.task.done():
            raise ValueError("ZEEK_ALREADY_ACTIVE")
        candidates = sorted(self.root.glob("session-*"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            return self.snapshot()
        self.directory = candidates[-1]
        self.writer = exclusive_runtime_lock(self.directory / "writer.lock")
        self.writer.__enter__()
        try:
            self.store = CollectorStore(self.directory)
            self.state = "RECOVERY_PENDING"
            self.recovery_state = "RECOVERY_PENDING"
            # Never restart Zeek or infer; replay only previously completed sanitized logs.
            with self.store.runtime.database.transaction(write=False) as c:
                completed = any(
                    json.loads(row[0])["kind"] == "ZEEK_OFFLINE_PROCESS_EXIT"
                    for row in c.execute("SELECT payload FROM monitor_audit")
                )
            if not completed:
                raise ValueError("ZEEK_PROCESS_COMPLETION_UNVERIFIED_NO_RESTART")
            await self._ingest()
            self.store.runtime.event(
                "COLLECTOR_RECOVERED",
                dict(native_capture=False, inference_count=0, automatic_restart=False),
            )
            self.state = "STOPPED"
            self.last_error = None
            self.recovery_state = "RESTORED_DIAGNOSTICS_ONLY"
            return self.snapshot()
        except (OSError, ValueError, StorageError, sqlite3.Error) as error:
            self.state = "ERROR"
            self.recovery_state = "BLOCKED"
            code = str(error)
            self.last_error = (
                code
                if code.startswith("ZEEK_") and len(code) <= 128 and code.replace("_", "").isalnum()
                else "ZEEK_RECOVERY_INTEGRITY_UNVERIFIED"
            )
            raise
        finally:
            self._release()


class FixtureCollector(ZeekCollector):
    """Same adapter/store/limits, with explicit synthetic provenance and no Zeek process."""

    async def prepare(self, *, logs: dict[str, bytes], mode="fixture") -> dict:
        if mode != "fixture":
            raise ValueError("ZEEK_FIXTURE_MODE_REQUIRED")
        return await self.prepare_logs(logs)

    async def prepare_logs(self, logs: dict[str, bytes]) -> dict:
        if self.task is not None and not self.task.done():
            raise ValueError("ZEEK_ALREADY_ACTIVE")
        logs = {"conn.log": b"", "dns.log": b"", **logs}
        for name, data in logs.items():
            if name not in {"conn.log", "dns.log"} or len(data) > 8 * 1024**2:
                raise ValueError("ZEEK_FIXTURE_BOUND")
            # Fixtures may be incomplete, but no private source strings may be persisted.
            if any(b'"' + key + b'"' in data for key in (b"query", b"answers", b"payload")):
                raise ValueError("ZEEK_FIXTURE_PRIVACY_REJECTED")
        from soc_agent.security_ai.research.models import digest

        create_private_directory(self.root)
        self.directory = self.root / ("session-" + uuid4().hex)
        create_private_directory(self.directory)
        create_private_directory(self.directory / "logs")
        source = Source(
            session_id=uuid4(),
            source_digest=digest(
                {k: __import__("hashlib").sha256(v).hexdigest() for k, v in logs.items()}
            ),
            origin="SYNTHETIC_ZEEK_JSON",
            version=VERSION,
        )
        self.writer = exclusive_runtime_lock(self.directory / "writer.lock")
        self.writer.__enter__()
        self.store = CollectorStore(self.directory, source)
        for name, data in logs.items():
            if name not in {"conn.log", "dns.log"} or len(data) > 8 * 1024**2:
                raise ValueError("ZEEK_FIXTURE_BOUND")
            path = self.directory / "logs" / name
            path.write_bytes(data)
            path.chmod(0o600)
        self.store.runtime.event(
            "ZEEK_OFFLINE_PROCESS_EXIT",
            dict(
                fixture=True,
                native_capture=False,
                log_sha256={
                    p.name: __import__("hashlib").sha256(p.read_bytes()).hexdigest()
                    for p in (self.directory / "logs").glob("*.log")
                },
            ),
        )
        self.state = "READY_OFFLINE"
        return self.snapshot()

    async def start(self) -> dict:
        if self.state != "READY_OFFLINE":
            raise ValueError("ZEEK_NOT_PREPARED")
        self.state = "OFFLINE_PROCESSING"
        self.task = asyncio.create_task(self._fixture())
        return self.snapshot()

    async def _fixture(self):
        try:
            await self._ingest()
            self.state = "STOPPED"
            self.store.runtime.event("COLLECTOR_COMPLETED", dict(fixture=True, inference_count=0))
        except (ValueError, OSError) as error:
            self.last_error = (
                str(error) if str(error).startswith("ZEEK_") else "ZEEK_FIXTURE_SCHEMA_REJECTED"
            )
            self.state = "ERROR"
            self.store.runtime.event("COLLECTOR_FAILED", dict(error=self.last_error))
        finally:
            self._release()
