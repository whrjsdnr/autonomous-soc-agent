"""Sanitized actual failure/source snapshots, not fabricated complete investigations."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Annotated, Literal
from uuid import UUID

from pydantic import Field, JsonValue

from soc_agent.linux_runtime.findings import correlate, validate_finding
from soc_agent.security_ai.external.models import Hash, Snapshot, content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.source_records import AuthenticationSource
from soc_agent.state.evidence import UTCTimestamp

if TYPE_CHECKING:
    from soc_agent.investigation.models import InvestigationResult
    from soc_agent.linux_runtime.models import Finding
    from soc_agent.linux_runtime.service import LinuxMonitor
    from soc_agent.linux_runtime.store import RuntimeStore

LLM_CODES = {
    "LLMTimeoutError": "TIMEOUT",
    "LLMNetworkError": "NETWORK_ERROR",
    "LLMProviderError": "PROVIDER_ERROR",
    "LLMResponseValidationError": "RESPONSE_VALIDATION_ERROR",
}
TOOL_CODES = {
    "ToolTimeoutError": "TOOL_TIMEOUT",
    "ToolExecutionError": "TOOL_ERROR",
    "ToolInputValidationError": "TOOL_ERROR",
    "ToolOutputValidationError": "TOOL_ERROR",
    "ExecutionDeniedError": "READ_CAPABILITY_DENIED",
}


class FailureQuery(Snapshot):
    kind: Literal["SUSPECTED_MISS", "LLM_FAILURE", "TOOL_FAILURE", "INVESTIGATION_FAILURE"]
    incident_id: UUID
    finding_id: Hash | None = None
    event_references: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = Field(
        default=(), max_length=64
    )
    expected_rule: (
        Literal[
            "REPEATED_AUTH_FAILURE",
            "REPEATED_ACCOUNT_FAILURE",
            "MULTI_ACCOUNT_FAILURE",
            "FAILURE_THEN_SUCCESS",
            "SUDO_PAM_MODULE_FAILURE",
        ]
        | None
    ) = None
    window_start: UTCTimestamp | None = None
    window_end: UTCTimestamp | None = None
    independent_label_reference: Hash | None = None


def _seal(body: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return body | {"experience_id": content_digest_payload(body)}


def capture_failure(monitor: LinuxMonitor, query: FailureQuery) -> dict[str, JsonValue]:
    query = FailureQuery.model_validate(query.model_dump())
    if query.incident_id != monitor.config.incident_id:
        raise ValueError("FAILURE_INCIDENT_BINDING_REJECTED")
    monitor.store.verify_audit()
    read_authentication_view(monitor.pipeline)  # Queue/source/window/native receipts fail closed.
    if query.kind == "SUSPECTED_MISS":
        if (
            query.finding_id is not None
            or not query.event_references
            or len(set(query.event_references)) != len(query.event_references)
        ):
            raise ValueError("FN_SOURCE_REFERENCES_REQUIRED")
        if (
            query.window_start is None
            or query.window_end is None
            or query.expected_rule is None
            or query.window_start.timestamp() % 300
            or query.window_end - query.window_start != timedelta(minutes=5)
        ):
            raise ValueError("FN_WINDOW_RULE_REJECTED")
        # No external verified-label provider exists. Do not accept a hash as verification.
        if query.independent_label_reference is not None:
            raise ValueError("INDEPENDENT_FN_LABEL_VERIFICATION_UNAVAILABLE")
        with monitor.pipeline.store.database.transaction(write=False) as c:
            sources = [
                monitor.pipeline.store._decode(r)
                for r in c.execute(
                    "SELECT * FROM operational_sources WHERE incident_id=? AND status='ACCEPTED'",
                    (str(query.incident_id),),
                )
            ]
        selected = [s for s in sources if s.header.event_id in query.event_references]
        if len(selected) != len(query.event_references) or any(
            not isinstance(s, AuthenticationSource)
            or not query.window_start <= s.header.observed_at < query.window_end
            for s in selected
        ):
            raise ValueError("FN_UNSUPPORTED_OR_FOREIGN_SOURCE")
        from soc_agent.security_ai.operational.native_authentication import PAM_PROFILE

        with monitor.pipeline.queue.database.transaction(write=False) as c:
            profiles = {
                str(event.event_id): dict(event.normalized_fields).get("parser")
                for row in c.execute("SELECT * FROM realtime_events WHERE status='DONE'")
                for event in (monitor.pipeline.queue._decode(row),)
            }
        if any(
            (profiles.get(s.header.event_id) == PAM_PROFILE)
            != (query.expected_rule == "SUDO_PAM_MODULE_FAILURE")
            for s in selected
        ):
            raise ValueError("FN_RULE_SOURCE_SEMANTICS_MISMATCH")
        # A not-yet-published real detection is not an FN either.
        if any(
            f.rule_id == query.expected_rule
            and set(f.event_references) & set(query.event_references)
            for f in correlate(monitor.pipeline, monitor.config)
        ):
            raise ValueError("EXPECTED_DETECTION_ALREADY_PRESENT")
        references = sorted(s.content_digest for s in selected)
        return _seal(
            {
                "contract_version": "soc-runtime-failure-experience:v1",
                "kind": query.kind,
                "incident_id": str(query.incident_id),
                "finding_id": None,
                "event_references": sorted(query.event_references),
                "source_references": references,
                "source_digest": content_digest_payload({"sources": references}),
                "query": query.model_dump(mode="json"),
                "category": "SUSPECTED_MISS",
                "label_assurance": "NO_INDEPENDENT_GROUND_TRUTH",
                "inference_status": "NOT_INFERABLE",
                "authority": "NONE",
            }
        )
    if (
        query.finding_id is None
        or query.event_references
        or query.independent_label_reference is not None
        or query.expected_rule is not None
        or query.window_start is not None
        or query.window_end is not None
    ):
        raise ValueError("FAILURE_FINDING_BINDING_REQUIRED")
    with monitor.store.database.transaction(write=False) as c:
        row = c.execute("SELECT * FROM monitor_findings WHERE id=?", (query.finding_id,)).fetchone()
        if row is None:
            raise ValueError("FAILURE_FINDING_MISSING")
        finding = monitor.store._decode(row)
        if row["status"] not in ("FAILED", "BLOCKED") or row["result"] is None:
            raise ValueError("TERMINAL_FAILURE_REQUIRED")
        result = json.loads(row["result"])
        attempt = row["attempts"]
        events = [
            json.loads(r[0])
            for r in c.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
        ]
    validate_finding(monitor.pipeline, finding)
    if result.get("write_disposition") != "WRITE_DENIED":
        raise ValueError("FAILURE_WRITE_BOUNDARY_REJECTED")
    receipts = [
        e
        for e in events
        if e["details"].get("finding") == query.finding_id
        and e["details"].get("attempt") == attempt
    ]
    proof = None
    category = None
    if query.kind == "LLM_FAILURE":
        proof = next(
            (
                e
                for e in reversed(receipts)
                if e["kind"] in ("LLM_INVOCATION_FAILED", "LLM_BUDGET_EXCEEDED")
            ),
            None,
        )
        if proof:
            category = (
                "BUDGET_EXCEEDED"
                if proof["kind"] == "LLM_BUDGET_EXCEEDED"
                else LLM_CODES.get(proof["details"].get("category"))
            )
    elif query.kind == "TOOL_FAILURE":
        proof = next((e for e in reversed(receipts) if e["kind"] == "READ_TOOL_FAILURE"), None)
        if proof and proof["details"].get("tool") == "read_authentication_context":
            category = proof["details"].get("category")
            if category not in set(TOOL_CODES.values()):
                category = None
    else:
        category = (
            "INVESTIGATION_FAILED"
            if result.get("failure_code") == "INVESTIGATION_FAILURE"
            else None
        )
    if category is None:
        raise ValueError("UNPROVEN_OR_MISCLASSIFIED_FAILURE")
    return _seal(
        {
            "contract_version": "soc-runtime-failure-experience:v1",
            "kind": query.kind,
            "incident_id": str(query.incident_id),
            "finding_id": finding.finding_id,
            "finding_digest": finding.digest,
            "query": query.model_dump(mode="json"),
            "event_references": list(finding.event_references),
            "source_references": list(finding.evidence_references),
            "result_digest": row["result_digest"],
            "attempt": attempt,
            "category": category,
            "failure_audit_reference": content_digest_payload(proof) if proof else None,
            "label_assurance": "OBSERVED_RUNTIME_FAILURE_NOT_ATTACK_LABEL",
            "inference_status": "NOT_INFERABLE",
            "authority": "NONE",
        }
    )


def record_read_failures(
    store: RuntimeStore, finding: Finding, attempt: int, investigation: InvestigationResult | None
) -> None:
    if investigation is None:
        return
    for step in investigation.plan.steps:
        if step.tool_name != "read_authentication_context" or step.failure is None:
            continue
        category = TOOL_CODES.get(step.failure.error_type)
        if category:
            store.invocation_event(
                finding,
                attempt,
                "READ_TOOL_FAILURE",
                {
                    "tool": step.tool_name,
                    "category": category,
                    "step_reference": content_digest_payload(step.model_dump(mode="json")),
                },
            )
