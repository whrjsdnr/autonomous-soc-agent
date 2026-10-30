"""Adapters from Continuous results into the existing ApplicationService/SOCRuntime.

There is no second workflow engine here. Scheduling uses EventQueue; execution,
planning, assessment, claims and recovery remain in the existing core runtime.
"""

import asyncio
import json
import threading
import time
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel

from soc_agent.adaptive import AdaptiveInvestigationPlanner, InvestigationContext
from soc_agent.api.models import StepRequest
from soc_agent.api.startup import open_store
from soc_agent.application import compose_application
from soc_agent.continuous.investigation_models import (
    CoordinationAdvice,
    InvestigationSource,
    InvestigationTask,
)
from soc_agent.continuous.investigation_store import InvestigationTasks
from soc_agent.deployment import DeploymentDescriptor
from soc_agent.desktop import OfflineDesktopClient, ReadReportInput
from soc_agent.llm import LLMClient, LLMError, LLMRequest
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.errors import PlanningReviewRequired
from soc_agent.review.persistence.models import StorageError
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai import SecurityAIRegistry
from soc_agent.security_ai.external.runtime_store import RuntimeGovernanceStore
from soc_agent.security_ai.offline_workflow import verify_result
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import JOB
from soc_agent.state import Evidence, IncidentState
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry


def from_analysis(directory: Path, *, scope: str, namespace: str) -> InvestigationSource:
    """Verify retained model receipts before publishing any orchestration input."""
    outcome = verify_result(directory)
    job = JOB.validate_json(read_local(directory / "input.json", 1024**2))
    raw = job.model_dump(mode="json")
    domain = {e.domain for e in outcome.evidence}
    role = (
        "AUTHENTICATION" if "AUTHENTICATION" in domain else "DNS" if "DNS" in domain else "NETWORK"
    )
    target = event_ns = None
    clock = "UNKNOWN"
    if raw["kind"] == "packet_window":
        first = raw["packets"][0]
        target = digest(str(first["source_address"]))
        event_ns = first.get("capture_timestamp_ns")
        if event_ns is None:
            from datetime import datetime

            stamp = datetime.fromisoformat(first["timestamp"])
            event_ns = int(stamp.timestamp()) * 10**9 + stamp.microsecond * 1000
        clock = "UTC"
    elif raw["kind"] == "raw_dns":
        first = next((m for m in raw["messages"] if m["destination_port"] == 53), None)
        if first:
            target, event_ns = digest(str(first["source_address"])), first["timestamp_ns"]
            clock = raw["clock_epoch"]
    elif raw["kind"] == "authentication_window":
        from ipaddress import ip_address

        identifiers = {r.payload().get("source_identifier") for r in job.records}
        if len(identifiers) == 1:
            try:
                target = digest(str(ip_address(next(iter(identifiers)))))
            except (ValueError, TypeError):
                target = None
        event_ns = int(job.records[0].observed_at.timestamp()) * 10**9
        clock = "UTC"
    # TCX timestamps are monotonic. Never correlate them with DNS/journal UTC
    # merely because they arrived in the same service; no invented clock mapping.
    origin = next(iter({e.origin for e in outcome.evidence}), "UNKNOWN")
    if len({e.origin for e in outcome.evidence}) > 1:
        origin = "MIXED_RETAINED_ORIGINS"
    observed = min((e.observed_at for e in outcome.evidence if e.observed_at), default=None)
    if observed is None:
        retained_store = RuntimeGovernanceStore(directory / "soc/external-validation.sqlite")
        with retained_store.database.transaction(write=False) as c:
            completed = [
                json.loads(row[0])
                for row in c.execute("SELECT payload FROM external_security_audit")
                if json.loads(row[0])["code"] == "OFFLINE_ANALYSIS_COMPLETED"
            ]
        from datetime import datetime

        observed = datetime.fromisoformat(completed[-1]["created_at"])
    return InvestigationSource(
        incident_id=outcome.incident_id,
        role=role,
        origin=origin,
        namespace=namespace,
        scope=scope,
        reference=digest(raw),
        observed_at=observed,
        target=target,
        event_ns=event_ns,
        clock=clock,
        advisory=dict(
            classification=outcome.classification,
            reasons=list(outcome.reasons),
            eligibility=outcome.eligibility,
            agreement_state=(outcome.fusion or {}).get("agreement_state", "insufficient"),
            model_results=[
                r.model_dump(mode="json", exclude={"receipt"}) for r in outcome.inference
            ],
            evidence=[e.model_dump(mode="json") for e in outcome.evidence],
            original_result_digest=digest(outcome.model_dump(mode="json")),
            known_error_response={
                k: v
                for k, v in (outcome.response or {}).items()
                if k in ("status", "postcondition", "host_remediation")
            },
            llm_mode=outcome.llm_mode,
            model_authority="NO_NEW_MODEL_ACTION",
        ),
    )


class ScriptedCoordinationClient(OfflineDesktopClient):
    """Explicit local scripted proposals. No provider, key discovery or API fallback."""

    async def generate_structured(self, *, request, response_model):
        if response_model is CoordinationAdvice:
            return CoordinationAdvice(
                priority=1,
                additional_evidence_required=True,
                reason="SCRIPTED: inspect retained source; independent verification required",
                requested_roles=("INVESTIGATION",),
                strategy="READ_RETAINED_EVIDENCE",
            )
        from soc_agent.adaptive.models import ReplanningDraft

        if response_model is ReplanningDraft:
            body = json.loads(request.user_prompt)
            if body.get("TOOL INVESTIGATION HISTORY (UNTRUSTED DATA)"):
                return ReplanningDraft(
                    decision="escalate_to_human",
                    reason="SCRIPTED: source inspected; independent evidence required",
                )

            # Existing planner projections contain the current incident ID.
            def incident(value):
                if isinstance(value, dict):
                    if "incident_id" in value:
                        return value["incident_id"]
                    for nested in value.values():
                        found = incident(nested)
                        if found:
                            return found
                return None

            return ReplanningDraft.model_validate(
                dict(
                    decision="continue_with_tool",
                    reason="SCRIPTED: inspect evidence behind conflicting results",
                    tool=dict(
                        tool_name="read_local_source_report",
                        tool_input=dict(incident_id=incident(body)),
                        purpose="Read retained provenance",
                    ),
                )
            )
        return await super().generate_structured(request=request, response_model=response_model)


class SourceContextClient:
    """Keep model advisory separate from source facts; record only request digests."""

    def __init__(self, client: LLMClient, sources: list[InvestigationSource]):
        self.client, self.sources = client, sources

    async def generate_structured(self, *, request: LLMRequest, response_model: type[BaseModel]):
        body = json.loads(request.user_prompt)
        body["CONTINUOUS ADVISORY (NOT FACTS OR AUTHORITY)"] = [
            dict(
                incident_id=str(s.incident_id), source=s.reference, role=s.role, advisory=s.advisory
            )
            for s in self.sources
        ]
        projected = LLMRequest(
            system_prompt=request.system_prompt
            + " Read-only proposals only. Model results are not facts."
            " Never issue approvals, Root commands, capture instructions or claim proven attacks.",
            user_prompt=json.dumps(body, sort_keys=True),
        )
        if len(projected.user_prompt) > 64000:
            raise ValueError("CONTINUOUS_INVESTIGATION_CONTEXT_LIMIT")
        value = await self.client.generate_structured(
            request=projected, response_model=response_model
        )
        value = response_model.model_validate(value.model_dump())
        if getattr(value, "observations", ()):
            raise ValueError("CONTINUOUS_MODEL_FACT_PROMOTION_DENIED")
        return value


class ContinuousInvestigationPlanner(InvestigationPlanner):
    """Existing initial/replanning contracts invoked inside SOCRuntime's durable claim."""

    def __init__(self, *, task, tasks, client, registry, store):
        super().__init__(llm_client=client, registry=registry, max_steps=2)
        self.task, self.tasks, self.client, self.registry, self.store = (
            task,
            tasks,
            client,
            registry,
            store,
        )

    async def create_plan(self, incident_state):
        advice = await self.client.generate_structured(
            request=LLMRequest(
                system_prompt="Propose a bounded investigation priority and evidence strategy.",
                user_prompt=json.dumps(
                    dict(incident_id=str(incident_state.incident_id), conflict=self.task.conflict)
                ),
            ),
            response_model=CoordinationAdvice,
        )
        self.tasks.service.event_once(
            "CONTINUOUS_COORDINATION_ADVICE",
            dict(
                task_id=str(self.task.task_id),
                evidence_revision=self.task.revision,
                advice=advice.model_dump(mode="json"),
                authority="ADVISORY_ONLY",
            ),
        )
        if advice.strategy == "ESCALATE":
            raise PlanningReviewRequired("CONTINUOUS_ADVICE_REQUIRES_HUMAN_REVIEW")
        # History is derived from the authoritative current incident. Core's
        # attempted-input guard remains the cross-call no-repeat boundary.
        if self.task.conflict or getattr(self, "history", None) is not None:
            adaptive = AdaptiveInvestigationPlanner(
                llm_client=self.client,
                tool_registry=self.registry,
                ai_registry=SecurityAIRegistry(),
            )
            proposed = await adaptive.replan(
                InvestigationContext(
                    incident=incident_state,
                    tool_history=(self.history,) if getattr(self, "history", None) else (),
                )
            )
            self.tasks.service.event_once(
                "CONTINUOUS_REPLAN_PROPOSED",
                dict(
                    task_id=str(self.task.task_id),
                    proposal=proposed.model_dump(mode="json"),
                ),
            )
            if proposed.next_tool_plan is None:
                raise PlanningReviewRequired(
                    "CONTINUOUS_REPLAN_REQUIRES_EVIDENCE_OR_MODEL_ACTION_REVIEW"
                )
            return proposed.next_tool_plan
        return await super().create_plan(incident_state)

    async def create_followup(self, incident_state, history):
        self.history = history
        self.tasks.service.event_once(
            "CONTINUOUS_INVESTIGATION_HISTORY",
            dict(
                task_id=str(self.task.task_id),
                plan_id=str(history.plan_id),
                steps=[
                    dict(
                        tool=s.tool_name,
                        status=s.status.value,
                        error_type=s.failure.error_type if s.failure else None,
                    )
                    for s in history.steps
                ],
            ),
        )
        return await self.create_plan(incident_state)


def application(tasks: InvestigationTasks, task: InvestigationTask, client: LLMClient):
    root = tasks.directory / "workflows" / str(task.task_id)
    create_private_directory(root)
    path = root / "soc.sqlite"
    store = open_store(path, create=not path.exists())
    sources = [s for s in tasks.sources() if s.pin in task.sources]
    with store.database.transaction(write=False) as c:
        exists = c.execute(
            "SELECT 1 FROM incidents WHERE incident_id=?", (str(task.incident_id),)
        ).fetchone()
    if not exists:
        evidence = tuple(
            Evidence(
                evidence_id=uuid5(NAMESPACE_URL, "continuous-source:" + s.pin),
                incident_id=task.incident_id,
                source="continuous-source-link:v1",
                summary="Retained source link; related incident distinct; prediction advisory",
                raw_data=json.dumps(
                    dict(
                        source=s.reference,
                        original_incident_id=str(s.incident_id),
                        role=s.role,
                        origin=s.origin,
                        source_pin=s.pin,
                    )
                ),
                observed_at=s.observed_at,
            )
            for s in sources
        )
        store.register(IncidentState(incident_id=task.incident_id, evidence=evidence))
    registry = ToolRegistry()

    async def read(query: ReadReportInput):
        if query.incident_id != task.incident_id:
            raise ValueError("CONTINUOUS_SOURCE_INCIDENT_BINDING")
        actual = [s for s in tasks.sources() if s.pin in task.sources]
        if actual != sources:
            raise ValueError("CONTINUOUS_SOURCE_REVISION_CHANGED")
        return CoordinationAdvice(
            priority=task.priority,
            additional_evidence_required=True,
            requested_roles=task.roles,
            strategy="ASSESS",
            reason="Retained source hashes verified; independent verification still required",
        )

    registry.register(
        Tool(
            ToolMetadata(
                name="read_local_source_report",
                description="Read exact retained source references only",
                permission="file_read",
                risk_level="read_only",
            ),
            ReadReportInput,
            CoordinationAdvice,
            read,
        )
    )
    wrapped = SourceContextClient(client, sources)
    planner = ContinuousInvestigationPlanner(
        task=task, tasks=tasks, client=wrapped, registry=registry, store=store
    )
    return compose_application(
        store,
        deployment=DeploymentDescriptor(profile="DESKTOP"),
        registry=registry,
        llm_client=wrapped,
        investigation_planner=planner,
        investigate_first=True,
        replan_read_failures=True,
    ).service


async def advance_task(tasks, task, client, progress):
    service = application(tasks, task, client)
    with service.store.database.transaction(write=False) as c:
        exists = c.execute(
            "SELECT 1 FROM workflow_checkpoints WHERE incident_id=?", (str(task.incident_id),)
        ).fetchone()
    value = service.workflow(task.incident_id) if exists else service.start(task.incident_id)
    for _ in range(24):
        progress.update(
            task_id=str(task.task_id),
            incident_id=str(task.incident_id),
            evidence_revision=task.revision,
            step=value.next_step.value,
            checkpoint_revision=value.checkpoint_revision,
            heartbeat_unix=time.time(),
        )
        if value.waiting_for_human or value.terminal or value.failure:
            return value
        if not tasks.latest(task):
            return value  # Fresh revision runs separately, preserving this checkpoint.
        value = await asyncio.wait_for(
            service.step(
                task.incident_id,
                StepRequest(
                    run_id=value.workflow_id,
                    expected_revision=value.checkpoint_revision,
                ),
            ),
            30,
        )
    raise ValueError("CONTINUOUS_INVESTIGATION_STEP_LIMIT")


def checkpoint_view(tasks: InvestigationTasks, task: InvestigationTask) -> dict:
    """Bounded display of the verified core checkpoint; full evidence stays in core."""
    from soc_agent.investigation.runtime.persistence import CheckpointStore
    from soc_agent.review.persistence import SQLiteGovernanceStore

    store = SQLiteGovernanceStore(tasks.directory / "workflows" / str(task.task_id) / "soc.sqlite")
    checkpoint, trace = CheckpointStore(store).load(task.incident_id)
    assessment = checkpoint.artifacts.assessment
    plan = checkpoint.artifacts.investigation
    return dict(
        checkpoint_revision=checkpoint.revision,
        assessment=dict(
            threat_assessment=assessment.threat_assessment.model_dump(mode="json"),
            incident_state=dict(
                evidence=[
                    e.model_dump(mode="json", include={"evidence_id", "tool_name", "summary"})
                    for e in assessment.incident_state.evidence[-4:]
                ]
            ),
        )
        if assessment
        else None,
        plan=dict(
            plan_id=str(plan.plan_id),
            steps=[dict(tool=s.tool_name, status=s.status.value) for s in plan.steps],
        )
        if plan
        else None,
        timeline=dict(
            entries=[
                dict(content=dict(result=dict(reason=e.content.result.reason)))
                for e in trace.entries[-4:]
            ]
        ),
        evidence_references=list(task.sources),
        view_scope="BOUNDED_CHECKPOINT_PROJECTION_FULL_EVIDENCE_RETAINED",
    )


async def observed_task(tasks, task, provider, progress):
    """Worker liveness is not LLM completion; keep both visible while awaiting I/O."""
    operation = asyncio.create_task(advance_task(tasks, task, provider, progress))
    started = time.monotonic()
    try:
        async with asyncio.timeout(120):
            while not operation.done():
                await asyncio.wait((operation,), timeout=1)
                progress.update(
                    heartbeat_unix=time.time(),
                    heartbeat_scope="WORKER_SUPERVISOR_NOT_LLM_PROGRESS",
                    task_elapsed_seconds=time.monotonic() - started,
                )
                if (status := getattr(provider, "api_status", None)) is not None:
                    progress["api_status"] = status
            return operation.result()
    finally:
        operation.cancel()
        await asyncio.gather(operation, return_exceptions=True)


async def isolated_consume(tasks, stop, progress, *, shutdown_seconds=10, client=None):
    """Run existing core/SQLite work outside the Collector's asyncio loop.

    No new scheduler or execution authority: consume still owns its exact same
    claim, lock, checkpoints and bounded core steps. Unjoined I/O is UNVERIFIED.
    """
    owner = asyncio.get_running_loop()
    completed = owner.create_future()
    requested_stop, requested_cancel = threading.Event(), threading.Event()
    control = {}
    lock = threading.Lock()

    def request(cancel=False):
        requested_stop.set()
        if cancel:
            requested_cancel.set()
        with lock:
            if control:
                loop = control["loop"]
                try:
                    loop.call_soon_threadsafe(control["stop"].set)
                    if cancel:
                        loop.call_soon_threadsafe(control["task"].cancel)
                except RuntimeError:
                    if not loop.is_closed():
                        raise  # A closed owned loop is already completing, never restarted.

    def deliver(error):
        if not completed.done():
            if error is None:
                completed.set_result(None)
            else:
                completed.set_exception(error)

    def worker():
        async def run():
            local_stop = asyncio.Event()
            with lock:
                control.update(
                    loop=asyncio.get_running_loop(), stop=local_stop, task=asyncio.current_task()
                )
                if requested_stop.is_set():
                    local_stop.set()
                if requested_cancel.is_set():
                    asyncio.current_task().cancel()
            await consume(tasks, local_stop, progress, client=client)

        error = None
        try:
            asyncio.run(run())
        except BaseException as failure:
            error = failure
        finally:
            with lock:
                control.clear()
            try:
                owner.call_soon_threadsafe(deliver, error)
            except RuntimeError:
                if not owner.is_closed():
                    raise
                progress["late_worker_exit"] = "OWNER_CLOSED_REQUIRES_EVIDENCE_REVIEW"

    thread = threading.Thread(target=worker, daemon=True, name="soc-investigation-worker")
    progress["execution_scope"] = "DEDICATED_LOOP_NO_COLLECTOR_OR_ROOT_AUTHORITY"
    thread.start()
    cancel_deadline = None
    try:
        while not completed.done() and not stop.is_set():
            await asyncio.wait((completed,), timeout=0.1)
        if stop.is_set():
            request()
        await asyncio.shield(completed)
    except asyncio.CancelledError:
        cancel_deadline = time.monotonic() + min(2, shutdown_seconds)
        request(cancel=True)
        try:
            await asyncio.wait_for(
                asyncio.shield(completed), max(0, cancel_deadline - time.monotonic())
            )
        except asyncio.CancelledError:
            pass  # Expected cancellation of the owned coroutine, not a cleanup grant.
        except TimeoutError as error:
            completed.add_done_callback(
                lambda result: result.exception() if not result.cancelled() else None
            )
            progress["cleanup"] = "UNVERIFIED_THREAD_NOT_JOINED"
            raise ValueError("CONTINUOUS_INVESTIGATION_JOIN_UNVERIFIED") from error
        raise
    finally:
        join_seconds = (
            shutdown_seconds
            if cancel_deadline is None
            else max(0, cancel_deadline - time.monotonic())
        )
        await asyncio.to_thread(thread.join, join_seconds)
        if thread.is_alive():
            progress["cleanup"] = "UNVERIFIED_THREAD_NOT_JOINED"
            # Keep a waiter from being reported as a clean cancellation.
            raise ValueError("CONTINUOUS_INVESTIGATION_JOIN_UNVERIFIED")
        progress["cleanup"] = "VERIFIED_OWNED_WORKER_JOIN_ONLY"


async def consume(tasks, stop: asyncio.Event, progress: dict, *, client=None):
    provider = client or ScriptedCoordinationClient()
    provider_mode = getattr(provider, "evidence_mode", "INJECTED_CLIENT" if client else "SCRIPTED")
    # Independent lifetime; GUI disconnection has no effect on this lock or task.
    with exclusive_runtime_lock(tasks.directory / "worker.lock"):
        tasks.recover()
        while not stop.is_set():
            progress.update(heartbeat_unix=time.time(), provider=provider_mode)
            await asyncio.to_thread(tasks.schedule_retained)
            claim = await asyncio.to_thread(tasks.claim)
            if claim is None:
                progress.update(state="IDLE")
                await asyncio.sleep(0.1)
                continue
            task = tasks.task(claim)
            progress.update(state="RUNNING", task_id=str(task.task_id))
            try:
                result = None
                if tasks.latest(task):
                    result = await observed_task(tasks, task, provider, progress)
                state = (
                    "SUPERSEDED"
                    if not tasks.latest(task)
                    else (
                        "WAITING_HUMAN"
                        if result and result.waiting_for_human
                        else "FAILED"
                        if result and result.failure
                        else "COMPLETED"
                    )
                )
                investigation = checkpoint_view(tasks, task) if result else None
                api_status = getattr(provider, "api_status", None)
                if investigation is not None and api_status is not None:
                    investigation["api_status"] = api_status
                    progress["api_status"] = api_status
                details = dict(
                    task_id=str(task.task_id),
                    evidence_revision=task.revision,
                    state=state,
                    provider=provider_mode,
                    result=result.model_dump(mode="json") if result else None,
                    investigation=investigation,
                )
                tasks.service.event_once("CONTINUOUS_ORCHESTRATION_RESULT", details)
                tasks.queue.finish(
                    claim,
                    dict(
                        incident_id=str(task.incident_id),
                        workflow=state,
                        human_boundary=result.reason if result else "NEW_EVIDENCE_REVISION",
                    ),
                )
                progress.update(state=state)
            except asyncio.CancelledError:
                tasks.service.event(
                    "CONTINUOUS_ORCHESTRATION_CANCELLED",
                    dict(
                        task_id=str(task.task_id),
                        outcome="UNKNOWN_IF_STEP_CLAIMED_NO_AUTOMATIC_REPLAY",
                    ),
                )
                # Leave Claim and checkpoint intact; recovery never replays core in-flight work.
                raise
            except (ValueError, OSError, RuntimeError, LLMError, StorageError) as error:
                tasks.service.event(
                    "CONTINUOUS_ORCHESTRATION_FAILED",
                    dict(
                        task_id=str(task.task_id),
                        category=type(error).__name__,
                        reason="FIRST_FAILURE_PRESERVED_NO_AUTHORITY_OR_RETRY",
                    ),
                )
                tasks.queue.finish(
                    claim,
                    dict(
                        incident_id=str(task.incident_id),
                        workflow="BLOCKED",
                        human_boundary="CHECKPOINT_OR_INPUT_REVIEW_REQUIRED",
                    ),
                )
                progress.update(state="BLOCKED", error=type(error).__name__)
                if (api_status := getattr(provider, "api_status", None)) is not None:
                    progress["api_status"] = api_status
        progress.update(state="STOPPED", heartbeat_unix=time.time())
