"""Continuous task persistence over the existing Queue, private files and service Audit.

Related incidents remain distinct. Each evidence revision gets an immutable task
and an existing SOCRuntime repository; a new revision never resets an old claim.
"""

import json
import os
import tempfile
import threading
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel

from soc_agent.continuous.investigation_models import InvestigationSource, InvestigationTask
from soc_agent.realtime.models import CommonEvent, SourceIdentity, SourceMetadata
from soc_agent.realtime.queue import EventQueue, QueueFull
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def publish(path: Path, value: BaseModel) -> None:
    """Complete, fsynced immutable publication, including directory durability."""
    body = value.model_dump_json().encode()
    if path.exists():
        if read_local(path, 65536) != body:
            raise ValueError("CONTINUOUS_INVESTIGATION_IDENTITY_REUSE")
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".publish-", delete=False) as f:
            temporary = Path(f.name)
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.link(temporary, path)  # Never replace an existing task/source.
        fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


class InvestigationTasks:
    """Storage adapter only. Existing SOCRuntime owns investigation state transitions."""

    def __init__(self, service_store):
        self.service = service_store
        self._publication = threading.RLock()
        self.reschedule_pending = True
        self.directory = service_store.directory / "orchestration"
        create_private_directory(self.directory)
        for name in ("sources", "tasks", "workflows"):
            create_private_directory(self.directory / name)
        path = self.directory / "queue.sqlite"
        capacity = service_store.config.queue_capacity
        if not path.exists():
            self.queue = EventQueue.create(path, capacity=capacity, retry_limit=10)
        else:
            self.queue = EventQueue(path, capacity=capacity, retry_limit=10)

    def sources(self) -> list[InvestigationSource]:
        paths = list((self.directory / "sources").glob("*.json"))
        if len(paths) > self.service.config.max_windows:
            raise ValueError("CONTINUOUS_INVESTIGATION_RETENTION_LIMIT")
        result = []
        for path in sorted(paths):
            source = InvestigationSource.model_validate_json(read_local(path, 65536))
            if path.stem != source.pin:
                raise ValueError("CONTINUOUS_INVESTIGATION_SOURCE_SHA")
            result.append(source)
        return result

    def tasks(self) -> list[InvestigationTask]:
        paths = list((self.directory / "tasks").glob("*.json"))
        if len(paths) > self.service.config.max_windows:
            raise ValueError("CONTINUOUS_INVESTIGATION_TASK_RETENTION_LIMIT")
        result = []
        for path in sorted(paths):
            task = InvestigationTask.model_validate_json(read_local(path, 65536))
            if path.stem != str(task.task_id):
                raise ValueError("CONTINUOUS_INVESTIGATION_TASK_SHA")
            result.append(task)
        return result

    def submit(self, source: InvestigationSource) -> InvestigationTask:
        source = InvestigationSource.model_validate(source.model_dump())
        with self._publication, exclusive_runtime_lock(self.directory / "publish.lock"):
            old = self.sources()
            if source.pin not in {s.pin for s in old}:
                if len(old) >= self.service.config.max_windows:
                    raise ValueError("CONTINUOUS_INVESTIGATION_RETENTION_LIMIT")
                publish(self.directory / "sources" / (source.pin + ".json"), source)
            self.service.event_once(
                "CONTINUOUS_INVESTIGATION_SOURCE", source.model_dump(mode="json")
            )
            try:
                return self._schedule(source.group)
            except QueueFull:
                self.reschedule_pending = True
                raise

    def _schedule(self, group: str) -> InvestigationTask:
        members = [s for s in self.sources() if s.group == group]
        # A crash between immutable publication and Audit must not allow a task
        # to bypass its source record. event_once preserves existing history.
        for source in members:
            self.service.event_once(
                "CONTINUOUS_INVESTIGATION_SOURCE", source.model_dump(mode="json")
            )
        existing = [t for t in self.tasks() if t.group == group]
        owner = (
            min(existing, key=lambda t: t.created_at).incident_id
            if existing
            else members[0].incident_id
        )
        conflict = any(s.advisory.get("agreement_state") == "conflicting" for s in members)
        important = any(
            s.advisory.get("classification")
            in ("UNKNOWN_ANOMALY", "MODEL_ERROR", "COLLECTOR_ERROR")
            for s in members
        )
        pins = tuple(sorted(s.pin for s in members))
        previous = next((t for t in existing if t.sources == pins), None)
        task = previous or InvestigationTask(
            incident_id=owner,
            group=group,
            sources=pins,
            related_incidents=tuple(sorted({s.incident_id for s in members}, key=str)),
            roles=tuple(sorted({s.role for s in members} | {"INVESTIGATION"})),
            priority=2 if conflict else int(important),
            conflict=conflict,
            created_at=max(s.observed_at for s in members),
        )
        if not previous and len(self.tasks()) >= self.service.config.max_windows:
            raise ValueError("CONTINUOUS_INVESTIGATION_TASK_RETENTION_LIMIT")
        publish(self.directory / "tasks" / (str(task.task_id) + ".json"), task)
        identity = SourceIdentity(
            namespace="scenario:network:continuous-investigation",
            generation="v1",
            record=str(task.task_id),
        )
        event = CommonEvent(
            schema_version="soc-common-event:v2",
            event_id=uuid5(NAMESPACE_URL, content_digest(identity)),
            platform="validated_fixture",
            collector_id="scenario-network-capture:v1",
            event_type="os_record",
            event_timestamp=task.created_at,
            ingestion_timestamp=task.created_at,
            source=identity,
            metadata=SourceMetadata(
                channel="INTERNAL_TASK_REFERENCE", provider="soc-continuous:v1"
            ),
            normalized_fields=(
                ("task_id", str(task.task_id)),
                ("task_digest", digest(task.model_dump(mode="json"))),
            ),
            provenance="explicit_log_fixture",
        )
        fresh = self.queue.enqueue(event)
        self.service.event_once(
            "CONTINUOUS_INVESTIGATION_ENQUEUED"
            if fresh
            else "CONTINUOUS_INVESTIGATION_DUPLICATE_BLOCKED",
            dict(
                task=task.model_dump(mode="json"),
                duplicate=not fresh,
                transport="INTERNAL_REFERENCE_NOT_NATIVE_EVIDENCE",
            ),
        )
        return task

    def recover(self) -> None:
        # Caller holds the existing service lifetime lock. Core in-flight claims
        # are never cleared here: restoring such a task will require human review.
        self.queue.recover()
        self.schedule_retained()

    def schedule_retained(self) -> None:
        with self._publication, exclusive_runtime_lock(self.directory / "publish.lock"):
            if not self.reschedule_pending:
                return
            self.reschedule_pending = False
            for group in sorted({s.group for s in self.sources()}):
                try:
                    self._schedule(group)
                except QueueFull:
                    self.reschedule_pending = True
                    break  # Immutable sources remain available after the queue drains.

    def latest(self, task: InvestigationTask) -> bool:
        return task.sources == tuple(sorted(s.pin for s in self.sources() if s.group == task.group))

    def claim(self):
        tasks = {str(t.task_id): t for t in self.tasks()}
        with self.queue.database.transaction(write=False) as c:
            priorities = {
                UUID(row["event_id"]): self.bound_task(self.queue._decode(row), tasks).priority
                for row in c.execute("SELECT * FROM realtime_events WHERE status='PENDING'")
            }
        return self.queue.claim(priorities=priorities)

    def task(self, claim) -> InvestigationTask:
        return self.bound_task(claim.event, {str(t.task_id): t for t in self.tasks()})

    @staticmethod
    def bound_task(event, tasks) -> InvestigationTask:
        fields = dict(event.normalized_fields)
        task = tasks[fields["task_id"]]
        if fields["task_digest"] != digest(task.model_dump(mode="json")):
            raise ValueError("CONTINUOUS_TASK_CONTENT_SHA")
        return task

    def snapshot(self) -> dict:
        tasks = {str(t.task_id): t for t in self.tasks()}
        sources = self.sources()
        with self.service.database.transaction(write=False) as c:
            history = []
            for row in c.execute("SELECT digest,payload FROM continuous_details"):
                value = json.loads(row["payload"])
                if digest(value) != row["digest"]:
                    raise ValueError("CONTINUOUS_COORDINATION_AUDIT_CHANGED")
                if isinstance(value, dict) and "task_id" in value:
                    history.append(value)
        with self.queue.database.transaction(write=False) as c:
            rows = list(c.execute("SELECT * FROM realtime_events ORDER BY rowid DESC LIMIT 8"))
        result = []
        for row in rows:
            task = self.bound_task(self.queue._decode(row), tasks)
            outcome = json.loads(row["outcome"]) if row["outcome"] else {}
            completed = [
                v for v in history if v["task_id"] == str(task.task_id) and v.get("investigation")
            ]
            result.append(
                task.model_dump(mode="json")
                | dict(
                    task_id=str(task.task_id),
                    evidence_revision=task.revision,
                    state=outcome.get("workflow", row["status"]),
                    queue_state=row["status"],
                    waiting_reason=outcome.get("human_boundary"),
                    investigation=(
                        completed[-1]["investigation"]
                        | dict(
                            status=outcome.get("workflow", row["status"]),
                            llm_mode=completed[-1]["provider"],
                        )
                    )
                    if completed
                    else None,
                    dependencies=list(task.sources),
                    origin="SOURCE_RECORDS_SEE_TASK_PROVENANCE",
                    sources=[
                        dict(
                            role=s.role,
                            origin=s.origin,
                            reference=s.reference,
                            incident_id=str(s.incident_id),
                        )
                        for s in sources
                        if s.pin in task.sources
                    ],
                    decisions=[
                        self.decision_view(v) for v in history if v["task_id"] == str(task.task_id)
                    ][-3:],
                )
            )
        return dict(
            tasks=result,
            queue=self.queue.counts(),
            agents={
                role: "EVIDENCE_RETAINED"
                if any(s.role == role for s in sources)
                else "NOT_OBSERVED"
                for role in ("NETWORK", "DNS", "AUTHENTICATION")
            },
            authority="READ_ONLY_NO_MODEL_OR_ROOT_GRANTS",
            audit="SERVICE_AUDIT",
        )

    @staticmethod
    def decision_view(value):
        view = {k: value[k] for k in ("advice", "proposal", "state", "provider") if k in value}
        result = value.get("result")
        if result:
            view["result"] = {k: result[k] for k in ("next_step", "reason", "failure")}
        return view
