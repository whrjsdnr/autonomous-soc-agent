"""Read-only storage investigation, never model evidence or response authority."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from soc_agent.approval import ApprovalManager
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.investigation import (
    InvestigationOrchestrator,
    InvestigationPlan,
    InvestigationResult,
    InvestigationStep,
)
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import (
    NativeAuthenticationReceipt,
    authentication_source,
)
from soc_agent.security_ai.operational.provenance import build_receipt
from soc_agent.security_ai.operational.source_records import AuthenticationSource
from soc_agent.state import IncidentState
from soc_agent.state.evidence import UTCTimestamp
from soc_agent.tools import Tool, ToolMetadata, ToolRegistry

NAME = "read_authentication_context"


class AuthenticationReadQuery(Snapshot):
    incident_id: UUID
    expected_evidence_digest: Hash | None = None


class WindowReadView(Snapshot):
    account_reference: Hash
    started_at: UTCTimestamp
    ended_at: UTCTimestamp
    total: int = Field(ge=1)
    succeeded: int = Field(ge=0)
    failed: int = Field(ge=0)
    failure_rate: float = Field(ge=0, le=1, allow_inf_nan=False)
    login_attempt_rate: float = Field(gt=0, allow_inf_nan=False)
    source_reference: tuple[Hash, ...]
    evidence_digest: Hash
    provenance_reference: Hash


class AuthenticationReadView(Snapshot):
    contract_version: Literal["soc-authentication-read-view:v1"] = "soc-authentication-read-view:v1"
    incident_id: UUID
    source_reference: tuple[Hash, ...]
    authentication_window: tuple[WindowReadView, ...]
    queue_records_persisted: int
    authentication_events_verified: int
    authentication_events_unsupported: int
    authentication_events_rejected: int
    authentication_events_late_quarantined: int
    evidence_digest: Hash
    provenance_reference: tuple[Hash, ...]
    investigation_summary: str
    limitations: tuple[str, ...] = (
        "DECLARED_UNATTESTED sources; hashes verify continuity, not OS authenticity",
        "Journal entry timestamps do not prove exact authentication-attempt time",
        "Staging Incident association is not Core Incident Evidence approval",
        "No LLM or model inference; stored-log summary only",
        "Sudo pam_unix failure is a module-attempt outcome, not a final login/sudo denial",
    )
    inference_status: Literal["NOT_INFERABLE"] = "NOT_INFERABLE"
    action_policy: Literal["WRITE_DENIED"] = "WRITE_DENIED"


def read_authentication_view(pipeline: AuthenticationPipeline) -> AuthenticationReadView:
    """Recompute windows/provenance and verify every source against its retained queue event."""
    with pipeline.queue.database.transaction(write=False) as c:
        pipeline._binding(c)
        rows = c.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
        events = {}
        receipts = {}
        states = []
        unsupported = rejected = 0
        for row in rows:
            event = pipeline.queue._decode(row)
            events[str(event.event_id)] = event
            states.append({"event_id": str(event.event_id), "status": row["status"]})
            rejected += row["status"] == "POISON"
            unsupported += dict(event.normalized_fields).get("parse_status") == "NOT_INFERABLE"
            if row["status"] == "DONE":
                try:
                    outcome = json.loads(row["outcome"])
                    workflow = outcome["workflow"]
                    payload = workflow["receipt"]
                    if (
                        outcome["incident_id"] != str(pipeline.incident_id)
                        or outcome["inference"] != "NOT_INFERABLE"
                        or outcome["human_boundary"] != "WRITE_DENIED"
                        or content_digest_payload(payload) != workflow["digest"]
                    ):
                        raise ValueError
                    if "contract_version" in payload:
                        receipt = NativeAuthenticationReceipt.model_validate(payload)
                        receipts[str(event.event_id)] = receipt
                        if (
                            receipt.event_id != event.event_id
                            or receipt.incident_id != pipeline.incident_id
                            or receipt.native_projection_digest != event.source_digest
                            or receipt.raw_record_digest
                            != dict(event.normalized_fields)["raw_record_digest"]
                        ):
                            raise ValueError
                    elif (
                        set(payload) != {"status", "event_id", "source_digest"}
                        or payload["status"] != "NOT_INFERABLE"
                        or payload["event_id"] != str(event.event_id)
                        or payload["source_digest"] != event.source_digest
                    ):
                        raise ValueError
                except (ValueError, TypeError, KeyError) as error:
                    raise ValueError("AUTH_READ_RECEIPT_INTEGRITY_REJECTED") from error
    windows = pipeline.store.windows(pipeline.incident_id)
    with pipeline.store.database.transaction(write=False) as c:
        rows_source = c.execute(
            "SELECT * FROM operational_sources WHERE incident_id=?", (str(pipeline.incident_id),)
        ).fetchall()
        sources = {}
        late = 0
        for row in rows_source:
            source = pipeline.store._decode(row)
            late += row["status"] == "LATE_QUARANTINED"
            if not isinstance(source, AuthenticationSource):
                raise ValueError("AUTH_READ_SOURCE_TYPE_REJECTED")
            event = events.get(source.event.event_id)
            if (
                event is None
                or authentication_source(
                    event,
                    expected_event_digest=event.source_digest,
                    incident_id=pipeline.incident_id,
                )
                != source
            ):
                raise ValueError("AUTH_READ_QUEUE_SOURCE_LINK_REJECTED")
            linked = receipts.get(source.event.event_id)
            if (
                linked is None
                or linked.authentication_source_digest != source.content_digest
                or (
                    linked.provenance
                    != build_receipt(
                        pipeline.store, incident_id=pipeline.incident_id, sources=(source,)
                    )
                )
            ):
                raise ValueError("AUTH_READ_SOURCE_RECEIPT_LINK_REJECTED")
            sources[source.content_digest] = source
        if any(r.authentication_source_digest not in sources for r in receipts.values()):
            raise ValueError("AUTH_READ_REQUIRED_SOURCE_MISSING")
    views = []
    for window in windows:
        receipt = build_receipt(
            pipeline.store,
            incident_id=pipeline.incident_id,
            sources=tuple(sources[d] for d in window.source_digests),
            authentication=window,
        )
        values = window.window.features.input_payload()
        views.append(
            WindowReadView(
                account_reference=content_digest_payload({"account": window.window.account_id}),
                failure_rate=values["failure_rate"],
                login_attempt_rate=values["login_attempt_rate"],
                started_at=window.window.started_at,
                ended_at=window.window.ended_at,
                total=values["total_login_count"],
                succeeded=values["successful_login_count"],
                failed=values["failed_login_count"],
                source_reference=window.source_digests,
                evidence_digest=content_digest_payload(window.model_dump(mode="json")),
                provenance_reference=receipt.receipt_digest,
            )
        )
    body = {
        "incident_id": str(pipeline.incident_id),
        "events": sorted(e.source_digest for e in events.values()),
        "windows": [v.model_dump(mode="json") for v in views],
        "sources": sorted(sources),
        "queue_states": states,
    }
    return AuthenticationReadView(
        incident_id=pipeline.incident_id,
        source_reference=tuple(body["events"]),
        authentication_window=tuple(views),
        queue_records_persisted=len(events),
        authentication_events_verified=len(sources),
        authentication_events_unsupported=unsupported,
        authentication_events_rejected=rejected,
        authentication_events_late_quarantined=late,
        evidence_digest=content_digest_payload(body),
        provenance_reference=tuple(v.provenance_reference for v in views),
        investigation_summary=(
            f"Stored authentication windows={len(views)}; "
            f"mapped source records={len(sources)}; unsupported={unsupported}. "
            "No attack or response conclusion."
        ),
    )


class AuthenticationReadGuard:
    """Existing ToolGuard adapter: read-only catalog bound to one Incident."""

    def __init__(self, incident_id: UUID) -> None:
        self.incident_id = incident_id
        self.tool = None

    def planning_allowed(self, incident_id: object, metadata: object) -> bool:
        return (
            type(metadata) is ToolMetadata
            and incident_id == self.incident_id
            and metadata.name == NAME
            and metadata.is_read_only_capability
        )

    def bind_tool(self, tool: object) -> None:
        if (
            type(tool) is not Tool
            or self.tool is not None
            or tool.metadata.name != NAME
            or not tool.metadata.is_read_only_capability
        ):
            raise ExecutionDeniedError("AUTH_READ_TOOL_ALLOWLIST_DENIED")
        self.tool = tool
        object.__setattr__(tool, "execution_guard", self)

    def before_tool(self, tool: object) -> None:
        if (
            tool is not self.tool
            or tool.metadata.name != NAME
            or not tool.metadata.is_read_only_capability
        ):
            raise ExecutionDeniedError("AUTH_READ_WRITE_DENIED")

    def before_handler(self, tool: object, value: BaseModel) -> None:
        self.before_tool(tool)
        if type(value) is not AuthenticationReadQuery or value.incident_id != self.incident_id:
            raise ExecutionDeniedError("AUTH_READ_INCIDENT_DENIED")

    def action(self, action: object, operation: str) -> None:
        if (
            type(action) is not ActionProposal
            or action.incident_id != self.incident_id
            or action.tool_name != NAME
        ):
            raise ExecutionDeniedError("AUTH_READ_ACTION_DENIED")

    @contextmanager
    def dispatch(self, action: object, tool: object) -> Iterator[None]:
        self.action(action, "EXECUTE")
        self.before_tool(tool)
        yield


def authentication_read_registry(pipeline: AuthenticationPipeline) -> ToolRegistry:
    registry = ToolRegistry()
    registry.execution_guard = AuthenticationReadGuard(pipeline.incident_id)

    async def read(query: AuthenticationReadQuery) -> AuthenticationReadView:
        if query.incident_id != pipeline.incident_id:
            raise ValueError("AUTH_READ_INCIDENT_DENIED")
        view = read_authentication_view(pipeline)
        if (
            query.expected_evidence_digest is not None
            and view.evidence_digest != query.expected_evidence_digest
        ):
            raise ValueError("AUTH_READ_VIEW_DIGEST_MISMATCH")
        return view

    registry.register(
        Tool(
            ToolMetadata(
                name=NAME,
                description="Read verified storage links and declared authentication counts",
                permission="system_read",
                risk_level="read_only",
            ),
            AuthenticationReadQuery,
            AuthenticationReadView,
            read,
        )
    )
    return registry


async def investigate_authentication(pipeline: AuthenticationPipeline) -> InvestigationResult:
    """Existing orchestration/policy/approval/execution with one read step; no LLM."""
    view = read_authentication_view(pipeline)
    registry = authentication_read_registry(pipeline)
    executor = GovernedExecutor(
        registry=registry, policy=PolicyEngine(), approvals=ApprovalManager()
    )
    plan = InvestigationPlan(
        incident_id=pipeline.incident_id,
        steps=(
            InvestigationStep(
                tool_name=NAME,
                tool_input={
                    "incident_id": str(pipeline.incident_id),
                    "expected_evidence_digest": view.evidence_digest,
                },
                purpose="Read only authentication storage, counts and uncertainty",
            ),
        ),
    )
    result = await InvestigationOrchestrator(executor=executor).execute_plan(
        incident_state=IncidentState(incident_id=pipeline.incident_id),
        plan=plan,
        require_read_only=True,
    )
    return result
