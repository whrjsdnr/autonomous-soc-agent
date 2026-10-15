"""Explicit demo composition; existing secure DB/audit/checkpoints, no live Runtime writer."""

import asyncio
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import (
    create_private_directory,
    create_private_file,
    validate_directory,
)
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.runtime_store import (
    RuntimeGovernanceStore,
    audit,
    validate_audit,
)
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.environment import Paths, catalogue, read_local
from soc_agent.security_ai.research.investigation import investigate, verify_restored
from soc_agent.security_ai.research.models import Profile, Request, digest, parse_receipt


def write_new(path: Path, value: dict):
    with path.open("x") as stream:
        stream.write(json.dumps(value, sort_keys=True, allow_nan=False))
    path.chmod(0o600)


class ResearchDemo:
    def __init__(self, directory: Path, *, paths: Paths | None = None, timeout=30):
        self.directory = directory / "network-research"
        self.adapter = ResearchAdapter(self.directory, paths=paths, timeout=timeout)
        self.started = False
        self.running = False
        self.stopping = False
        self.active_key = None
        self.investigation_task = None

    def _store(self):
        root = self.directory / "soc"
        return RuntimeGovernanceStore(root / "external-validation.sqlite")

    def _records(self) -> tuple[list[dict], list[str]]:
        if not self.directory.exists():
            return [], []
        validate_directory(self.directory)
        attempts = list(self.directory.glob("attempt-*.json"))
        if len(attempts) > 10:
            raise ValueError("RESEARCH_REPLAY_CAPACITY")
        store = self._store()
        with store.database.transaction(write=False) as connection:
            validate_audit(connection)
            completed = [
                json.loads(r[0])["binding_digest"]
                for r in connection.execute(
                    "SELECT payload FROM external_security_audit "
                    "WHERE json_extract(payload,'$.code')='RESEARCH_COMPLETED' "
                    "ORDER BY sequence"
                )
            ]
            dispatched = [
                json.loads(r[0])["binding_digest"]
                for r in connection.execute(
                    "SELECT payload FROM external_security_audit "
                    "WHERE json_extract(payload,'$.code')='RESEARCH_DISPATCHED'"
                )
            ]
        if len(dispatched) != len(attempts) or any(
            digest(json.loads(read_local(p, 4096))) not in dispatched for p in attempts
        ):
            raise ValueError("RESEARCH_ATTEMPT_AUDIT_MISMATCH")
        records = []
        for path in self.directory.glob("receipt-*.json"):
            record = json.loads(read_local(path, 128 * 1024))
            if digest(record) not in completed:
                raise ValueError("RESEARCH_RECEIPT_AUDIT_MISMATCH")
            if record.get("receipt"):
                parse_receipt(record["receipt"])
            if record.get("investigation"):
                verify_restored(self._store(), record["investigation"])
            records.append(record)
        if len(records) != len(completed):
            raise ValueError("RESEARCH_AUDIT_RECEIPT_MISSING")
        keys = {r["key"] for r in records}
        unknown = [p.name[8:-5] for p in attempts if p.name[8:-5] not in keys]
        records.sort(key=lambda r: r["finished_at"])
        return records, unknown

    def snapshot(self):
        preflight = self.adapter.status()
        dns_status = self.adapter.status("dns")
        try:
            records, unknown = self._records()
        except (OSError, ValueError, StorageError, sqlite3.Error):
            return {
                "status": "UNKNOWN",
                "error": "RESEARCH_STORAGE_OR_AUDIT_INVALID",
                "records": [],
                "inference_counts": None,
                "operational_inference": "BLOCKED",
                "write_policy": "WRITE_DENIED",
            }
        unknown = [key for key in unknown if key != self.active_key]
        counts = {
            p: sum(bool(r.get("receipt")) and r["receipt"]["profile"] == p for r in records)
            for p in ("quality", "edge")
        }
        return {
            **preflight,
            "dns": dns_status,
            "model_metrics": self._model_metrics(records, unknown),
            "worker_running": self.adapter.process is not None
            and self.adapter.process.returncode is None,
            "active_model": getattr(self, "active_model", None),
            "dns_inference_count": sum(
                bool(r.get("receipt")) and r["receipt"]["profile"] == "dns" for r in records
            ),
            "demo_state": "STOPPING"
            if self.stopping
            else "RUNNING"
            if self.running
            else "STARTED"
            if self.started
            else "STOPPED",
            "records": records,
            "unknown_attempts": unknown,
            "inference_counts": counts,
            "errors": sum(r["status"] == "UNKNOWN" for r in records) + len(unknown),
            "audit_integrity": "VERIFIED" if self.directory.exists() else "NO_DATA",
            "flow_count": len(
                {
                    r["receipt"]["flow_id"]
                    for r in records
                    if r.get("receipt") and r["receipt"]["profile"] != "dns"
                }
            ),
            "source": "RESEARCH_ONLY_SEPARATE_OFFLINE_PCAP_AND_DNS9_FIXTURE_INPUTS",
        }

    def _model_metrics(self, records, unknown):
        metrics = {}
        for profile in ("quality", "edge", "dns"):
            rows = [
                r
                for r in records
                if r.get("profile", (r.get("receipt") or {}).get("profile")) == profile
            ]
            successes = [r["receipt"] for r in rows if r.get("receipt")]
            pending = 0
            for key in unknown:
                attempt = json.loads(
                    read_local(self.directory / ("attempt-" + key + ".json"), 4096)
                )
                pending += attempt["request"]["profile"] == profile
            metrics[profile] = {
                "successful": len(successes),
                "unknown": sum(not r.get("receipt") for r in rows) + pending,
                "last_inference": successes[-1]["inferred_at"] if successes else None,
                "last_error": next(
                    (r.get("error") for r in reversed(rows) if r.get("error")), None
                ),
                "state": "RUNNING"
                if getattr(self, "active_model", None) == profile
                and self.adapter.process is not None
                and self.adapter.process.returncode is None
                else "IDLE",
            }
        return metrics

    async def start(self, profile="quality"):
        if self.running:
            raise ValueError("RESEARCH_DEMO_ALREADY_RUNNING")
        status = await asyncio.to_thread(self.adapter.status, profile)
        if status["status"] != "READY":
            return status
        if not self.directory.exists():
            create_private_directory(self.directory, exist_ok=False)
            RuntimeGovernanceStore.create_isolated(self.directory / "soc")
            create_private_file(self.directory / "replay.lock")
        self._records()  # Corrupt/stale records cannot be silently reset.
        self.started, self.stopping = True, False
        return await asyncio.to_thread(self.snapshot)

    async def stop(self):
        self.started, self.stopping = False, self.running
        await self.adapter.cancel()
        if self.investigation_task is not None:
            self.investigation_task.cancel()
        return {
            "demo_state": "STOPPING" if self.running else "STOPPED",
            "operational_inference": "BLOCKED",
            "write_policy": "WRITE_DENIED",
        }

    async def replay(self, profile: Profile, flow_index: int):
        request = Request(
            research_mode=True,
            profile=profile,
            flow_index=flow_index,
            invocation_id=uuid4(),
            origin="FIXTURE" if profile == "dns" else "OFFLINE_PCAP",
        )
        if not self.started or self.stopping:
            raise ValueError("EXPLICIT_RESEARCH_START_REQUIRED")
        if self.running:
            raise ValueError("RESEARCH_REPLAY_ALREADY_RUNNING")
        self.running = True
        self.active_model = profile
        try:
            with exclusive_runtime_lock(self.directory / "replay.lock"):
                if profile == "dns":
                    from soc_agent.security_ai.research.dns import catalogue as dns_catalogue

                    sample = dns_catalogue()["fixtures"][flow_index]
                    key = digest({"profile": profile, "fixture_id": sample["id"]})
                else:
                    sample = catalogue()["samples"][flow_index]
                    key = digest({"profile": profile, "flow_id": sample["flow_id"]})
                records, unknown = self._records()
                cached = next((r for r in records if r["key"] == key), None)
                if cached:
                    return {"status": "CACHED_NO_NEW_INFERENCE", "record": cached}
                if key in unknown:
                    return {"status": "UNKNOWN", "error": "PREVIOUS_OUTCOME_UNKNOWN_NO_RETRY"}
                self.active_key = key
                attempt = {
                    "key": key,
                    "request": request.model_dump(mode="json"),
                    "created_at": datetime.now(UTC).isoformat(),
                }
                write_new(self.directory / ("attempt-" + key + ".json"), attempt)
                store = self._store()
                with store.database.transaction() as connection:
                    audit(connection, "RESEARCH_DISPATCHED", binding_digest=digest(attempt))
                outcome = await self.adapter.infer(request)
                result = {
                    "key": key,
                    "profile": profile,
                    "status": "UNKNOWN",
                    "finished_at": datetime.now(UTC).isoformat(),
                    "receipt": None,
                    "investigation": None,
                    "error": outcome.get("error"),
                }
                if outcome["status"] == "SUCCESS":
                    receipt = parse_receipt(outcome["receipt"])
                    result["receipt"] = receipt.model_dump(mode="json")
                    try:
                        if self.stopping:
                            raise ValueError("RESEARCH_DEMO_STOPPED")
                        self.investigation_task = asyncio.create_task(
                            investigate(store, receipt, uuid4())
                        )
                        result["investigation"] = await asyncio.wait_for(
                            self.investigation_task, 20
                        )
                        result["status"] = "COMPLETE"
                    except (ValueError, TimeoutError, asyncio.CancelledError):
                        result["error"] = "RESEARCH_INVESTIGATION_FAILED_NO_RETRY"
                write_new(self.directory / ("receipt-" + key + ".json"), result)
                with store.database.transaction() as connection:
                    audit(connection, "RESEARCH_COMPLETED", binding_digest=digest(result))
                return {"status": result["status"], "record": result}
        finally:
            self.running = False
            self.active_model = None
            self.stopping = False
            self.active_key = None
            self.investigation_task = None
