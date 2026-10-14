"""Single serial Linux monitor. Exclusive lifetime lock; bounded read-only investigations."""

import asyncio
import math
from datetime import timedelta
from pathlib import Path
from time import monotonic

from pydantic import ValidationError

from soc_agent.approval import ApprovalManager
from soc_agent.demo.scenario_analysis import analyze
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.linux_runtime.findings import correlate, validate_finding
from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.llm.errors import LLMResponseValidationError
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.policy import PolicyEngine
from soc_agent.realtime.queue import EventQueue
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import (
    authentication_read_registry,
    investigate_authentication,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.journal_health import collect_with_health
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.retention import MaintenanceLog
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.state.evidence import utc_now


def open_pipeline(directory: Path, config: RuntimeConfig):
    return AuthenticationPipeline(
        EventQueue(directory / "queue.sqlite"),
        OperationalSourceStore(
            directory / "sources.sqlite", allowed_lateness_seconds=60, max_future_skew_seconds=5
        ),
        config.incident_id,
        collector_identity="linux:journal:authentication:pam-failure:v1",
    )


def initialize(directory: Path, config: RuntimeConfig):
    directory = directory.resolve()
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("NONEMPTY_RUNTIME_DIRECTORY_NOT_ADOPTED")
    create_private_directory(directory)
    q = EventQueue.create(directory / "queue.sqlite")
    s = OperationalSourceStore.create(
        directory / "sources.sqlite", allowed_lateness_seconds=60, max_future_skew_seconds=5
    )
    p = AuthenticationPipeline(
        q, s, config.incident_id, collector_identity="linux:journal:authentication:pam-failure:v1"
    )
    MaintenanceLog.create(directory / "collection-audit.sqlite", p)
    return RuntimeStore.create(directory, config)


class BudgetClient:
    def __init__(self, client, config):
        self.client, self.config, self.calls = client, config, 0
        self.usage = []

    async def generate_structured(self, *, request, response_model):
        if self.calls >= self.config.max_llm_calls:
            raise LLMResponseValidationError("LLM_CALL_LIMIT")
        self.calls += 1
        response = await self.client.generate_structured(
            request=request, response_model=response_model
        )
        usage = getattr(self.client, "last_usage", None)
        self.usage.append(dict(usage) if isinstance(usage, dict) else None)
        if hasattr(response, "steps") and len(response.steps) > self.config.max_tool_calls:
            raise LLMResponseValidationError("TOOL_CALL_LIMIT")
        return response


class LinuxMonitor:
    def __init__(self, directory: Path, *, collector=None, llm_client=None):
        self.directory = directory.resolve()
        self.store = RuntimeStore(self.directory)
        self.config = self.store.config
        self.pipeline = open_pipeline(self.directory, self.config)
        self.audit = MaintenanceLog(self.directory / "collection-audit.sqlite", self.pipeline)
        self.collector = collector or LinuxAuthenticationCollector(include_pam_failures=True)
        self.stop_event = asyncio.Event()
        saved = self.store.state()
        self.collection_failures = saved.get("collection_failures", 0)
        self.llm_failures = saved.get("llm_failures", 0)
        self.circuit_open = saved.get("circuit_open", False)
        self.client = llm_client
        if self.config.assessment_mode == "REAL_LLM" and self.client is None:
            try:
                self.client = OpenAICompatibleClient(
                    OpenAICompatibleSettings(_env_file=self.config.env_file)
                )
            except ValidationError:
                self.store.update(llm="NOT_CONFIGURED", last_error="LLM_CONFIGURATION_UNAVAILABLE")

    def request_stop(self):
        self.stop_event.set()

    async def investigate_one(self):
        if self.circuit_open:
            return
        if self.config.assessment_mode == "REAL_LLM" and self.client is None:
            self.store.update(llm="NOT_CONFIGURED", last_error="LLM_CONFIGURATION_UNAVAILABLE")
            return
        claimed = self.store.claim()
        if not claimed:
            return
        finding, attempt = claimed
        budget = BudgetClient(self.client, self.config) if self.client else None
        failure_code = "SOURCE_VALIDATION_FAILURE"
        try:
            validate_finding(self.pipeline, finding)
            if self.config.assessment_mode == "READ_ONLY":
                investigation = await asyncio.wait_for(
                    investigate_authentication(self.pipeline),
                    timeout=self.config.investigation_seconds,
                )
                if not all(step.status.value == "completed" for step in investigation.plan.steps):
                    raise ValueError("READ_INVESTIGATION_FAILED")
                result = {
                    "finding_digest": finding.digest,
                    "mode": "READ_ONLY",
                    "investigation": investigation.model_dump(mode="json"),
                    "investigation_digest": content_digest_payload(
                        investigation.model_dump(mode="json")
                    ),
                    "llm_calls": 0,
                    "token_usage": None,
                    "cost_estimate": None,
                    "write_disposition": "WRITE_DENIED",
                }
                status = "DONE_READ_ONLY"
            else:
                investigation, assessment, stages, exchanges = await asyncio.wait_for(
                    analyze(
                        self.pipeline,
                        "REAL_LLM",
                        client=budget,
                        finding_context=finding.model_dump(mode="json"),
                    ),
                    timeout=self.config.investigation_seconds,
                )
                if any(stage.status != "PASS" for stage in stages.values()):
                    failure_code = stages["investigation"].outcome
                    raise ValueError("LLM_INVESTIGATION_BLOCKED")
                result = {
                    "finding_digest": finding.digest,
                    "mode": "REAL_LLM",
                    "investigation": investigation.model_dump(mode="json"),
                    "investigation_digest": content_digest_payload(
                        investigation.model_dump(mode="json")
                    ),
                    "assessment": assessment.model_dump(mode="json"),
                    "assessment_digest": content_digest_payload(assessment.model_dump(mode="json")),
                    "llm_exchanges": list(exchanges),
                    "llm_calls": budget.calls,
                    "token_usage": budget.usage,
                    "cost_estimate": None,
                    "write_disposition": "WRITE_DENIED",
                }
                status = "DONE"
            # Real execution boundary, not just a UI warning.
            executor = GovernedExecutor(
                registry=authentication_read_registry(self.pipeline),
                policy=PolicyEngine(),
                approvals=ApprovalManager(),
            )
            try:
                await executor.execute(
                    ActionProposal(
                        incident_id=self.config.incident_id,
                        tool_name="disable_demo_account",
                        tool_input={"account_id": "demo-alice"},
                    )
                )
            except ExecutionDeniedError:
                result["write_probe"] = "DENIED_HANDLER_NOT_REGISTERED"
            else:
                raise ValueError("READ_ONLY_BOUNDARY_BYPASS")
            self.store.finish(finding, status, result)
            self.llm_failures = 0
            self.store.update(llm_failures=0, circuit_open=False)
            self.store.update(
                last_investigation=utc_now().isoformat(),
                llm="AVAILABLE" if budget else "DISABLED",
                last_error=None,
            )
        except asyncio.CancelledError:
            self.store.finish(
                finding,
                "PENDING",
                {
                    "finding_digest": finding.digest,
                    "failure": "CANCELLED",
                    "llm_calls": budget.calls if budget else 0,
                    "token_usage": None,
                    "cost_estimate": None,
                },
            )
            raise
        except (TimeoutError, ValueError, StorageError, OSError) as error:
            self.llm_failures += 1
            retry = attempt <= self.config.investigation_retry_limit
            result = {
                "finding_digest": finding.digest,
                "failure": type(error).__name__,
                "failure_code": failure_code,
                "llm_calls": budget.calls if budget else 0,
                "token_usage": None,
                "cost_estimate": None,
            }
            self.store.finish(
                finding,
                "PENDING" if retry else "FAILED",
                result,
                next_attempt=utc_now() + timedelta(seconds=self.config.poll_seconds * 2**attempt)
                if retry
                else None,
            )
            self.circuit_open = self.llm_failures >= self.config.circuit_failures
            self.store.update(llm_failures=self.llm_failures, circuit_open=self.circuit_open)
            self.store.update(
                last_error=failure_code if isinstance(error, ValueError) else type(error).__name__,
                llm="CIRCUIT_OPEN" if self.circuit_open else "UNAVAILABLE",
                last_investigation=utc_now().isoformat(),
            )

    async def tick(self):
        if self.stop_event.is_set() or self.store.state()["stop_requested"]:
            return False
        health = collect_with_health(
            self.pipeline, self.collector, audit=self.audit, limit=self.config.batch_size
        )
        self.store.update(collector=health.status, cursor_health=health.status)
        if health.continuation_allowed:
            self.collection_failures = 0
            self.store.update(last_collection=utc_now().isoformat())
        elif health.status in (
            "GAP_DETECTED",
            "CURSOR_INVALID",
            "PERMISSION_DENIED",
            "STORE_FAILURE",
        ):
            self.store.event("COLLECTION_FATAL", {"status": health.status})
            raise ValueError(health.status)
        elif health.status != "BACKPRESSURE":
            self.collection_failures += 1
            self.store.event(
                "COLLECTION_RETRY", {"status": health.status, "attempt": self.collection_failures}
            )
            if self.collection_failures > self.config.collector_retry_limit:
                raise ValueError("COLLECTOR_RETRY_LIMIT")
        self.store.update(collection_failures=self.collection_failures)
        for _ in range(self.config.worker_batch):
            if self.stop_event.is_set() or self.store.state()["stop_requested"]:
                break
            if self.pipeline.step() == "IDLE":
                break
        if self.stop_event.is_set() or self.store.state()["stop_requested"]:
            return False
        for finding in correlate(self.pipeline, self.config):
            self.store.put(finding)
        await self.investigate_one()
        self.store.update(
            detection="IDLE", investigation="CIRCUIT_OPEN" if self.circuit_open else "IDLE"
        )
        return True

    async def run(self, *, duration_seconds: float | None = None):
        if duration_seconds is not None and (
            not math.isfinite(duration_seconds) or duration_seconds <= 0
        ):
            raise ValueError("RUNTIME_DURATION_INVALID")
        with exclusive_runtime_lock(self.directory / "writer.lock"):
            self.pipeline.queue.recover()
            self.store.recover()
            self.store.request_stop(False)
            self.store.update(state="RUNNING", started_at=utc_now().isoformat(), last_error=None)
            self.store.event("RUNTIME_STARTED", {"config": self.config.digest})
            start = monotonic()
            task = None
            try:
                while not self.stop_event.is_set():
                    if duration_seconds is not None and monotonic() - start >= duration_seconds:
                        break
                    task = asyncio.create_task(self.tick())
                    while not task.done():
                        await asyncio.sleep(0.1)
                        stopping = self.stop_event.is_set() or self.store.state()["stop_requested"]
                        stopping |= (
                            duration_seconds is not None and monotonic() - start >= duration_seconds
                        )
                        if stopping:
                            self.stop_event.set()
                            try:
                                await asyncio.wait_for(
                                    asyncio.shield(task), timeout=self.config.shutdown_seconds
                                )
                            except TimeoutError:
                                task.cancel()
                                await asyncio.gather(task, return_exceptions=True)
                            break
                    if task.cancelled() or not await task:
                        break
                    delay = self.config.poll_seconds * min(2**self.collection_failures, 16)
                    try:
                        await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
                    except TimeoutError:
                        continue
                self.store.update(state="STOPPING")
                self.store.event("RUNTIME_STOPPING", {})
                self.store.update(state="STOPPED")
                self.store.event("RUNTIME_STOPPED", {})
            except asyncio.CancelledError:
                if task is not None and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                self.store.update(state="STOPPED", last_error="CANCELLED")
                self.store.event("RUNTIME_CANCELLED", {})
                raise
            except (ValueError, StorageError, OSError) as error:
                self.store.update(state="FAILED", last_error=type(error).__name__)
                self.store.event("RUNTIME_FAILED", {"failure": type(error).__name__})
                raise
