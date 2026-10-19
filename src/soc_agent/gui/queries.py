"""Bounded, reference-first read projections. No SQL mutation or authority issuance."""

import json
from pathlib import Path

from soc_agent.gui.redaction import display_data
from soc_agent.linux_runtime.findings import validate_finding
from soc_agent.linux_runtime.service import open_pipeline
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.external.models import content_digest_payload


def investigation_rows(directory: Path, limit: int = 100) -> list[dict]:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("VIEW_LIMIT")
    store = RuntimeStore(directory)
    pipeline = open_pipeline(directory, store.config)
    with store.database.transaction(write=False) as connection:
        rows = list(
            connection.execute(
                "SELECT * FROM monitor_findings ORDER BY rowid DESC LIMIT ?", (limit,)
            )
        )
    items = []
    for row in rows:
        finding = store._decode(row)  # Existing state/result binding and digest validator.
        validate_finding(pipeline, finding)
        result = json.loads(row["result"]) if row["result"] else {}
        assessment = result.get("assessment") or {}
        items.append(
            display_data(
                {
                    "finding_id": finding.finding_id,
                    "incident_id": str(finding.incident_id),
                    "status": row["status"],
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "origin": finding.input_origin,
                    "assessment_mode": result.get("mode", store.config.assessment_mode),
                    "evidence_references": finding.evidence_references,
                    "provenance": finding.provenance,
                    "observations": {
                        "first_seen": finding.first_seen.isoformat(),
                        "last_seen": finding.last_seen.isoformat(),
                        "meaning": "Source references; finding is advisory, not attack fact",
                    },
                    "advisory_assessment": assessment,
                    "tool_steps": [
                        {
                            "tool_name": step.get("tool_name", "UNKNOWN"),
                            "status": step.get("status", "UNKNOWN"),
                        }
                        for step in result.get("investigation", {}).get("plan", {}).get("steps", [])
                    ],
                    "investigation_reference": result.get("investigation_digest"),
                    "error_category": result.get("failure"),
                    "result_digest": row["result_digest"],
                    "audit_reference": {"finding": finding.finding_id, "attempts": row["attempts"]},
                    "inference_status": "NOT_INFERABLE",
                    "action_policy": "WRITE_DENIED",
                }
            )
        )
    return items


def stored_counts(directory: Path) -> dict:
    """Storage metrics only; no conversion of row counts into verified attack facts."""
    store = RuntimeStore(directory)
    pipeline = open_pipeline(directory, store.config)
    with pipeline.store.database.transaction(write=False) as c:
        count = c.execute(
            "SELECT COUNT(*) FROM operational_sources WHERE incident_id=? "
            "AND status='ACCEPTED' AND json_extract(payload,'$.kind')='authentication'",
            (str(store.config.incident_id),),
        ).fetchone()[0]
    jobs = store.jobs()
    queue = pipeline.queue.counts()
    recent = investigation_rows(directory, 4)
    approvals = approval_rows(directory, False) + approval_rows(directory, True)
    return {
        "authentication_events": count,
        "findings_total": sum(jobs.values()),
        "collected_events": sum(queue.values()),
        "active_findings": sum(jobs.get(k, 0) for k in ("PENDING", "RUNNING")),
        "pending_approvals": None
        if len(approvals) >= 100
        else sum(r.get("status") == "PENDING_APPROVAL" for r in approvals),
        "investigation_distribution": jobs,
        "recent_activity": [
            {
                "rule_id": r["rule_id"],
                "event_time": r["observations"]["last_seen"],
                "origin": r["origin"],
            }
            for r in recent
        ],
    }


def approval_rows(directory: Path, restricted: bool) -> list[dict]:
    from soc_agent.linux_runtime.operator import view
    from soc_agent.linux_runtime.response_simulation import RuntimeResponseSimulation
    from soc_agent.linux_runtime.restricted_models import record_view
    from soc_agent.linux_runtime.restricted_response import RestrictedResponseExecutor
    from soc_agent.state.evidence import utc_now

    store = RuntimeStore(directory)
    pipeline = open_pipeline(directory, store.config)
    simulation = RuntimeResponseSimulation(store, pipeline)
    if restricted:
        with store.database.transaction(write=False) as c:
            records = RestrictedResponseExecutor.read_records(simulation._events(c))
        return [record_view(v, utc_now()) for v in list(records.values())[-100:]]
    return [view(v, simulation.clock()) for v in simulation.records()[-100:]]


def improvement_records(directory: Path, kind: str) -> list[dict]:
    """Read existing append-only audit artifacts; never evaluate, review or promote."""
    names = {"evaluations": "RUNTIME_OFFLINE_EVALUATION", "reviews": "RUNTIME_CANDIDATE_REVIEW"}
    if kind not in names:
        raise ValueError("UNKNOWN_IMPROVEMENT_VIEW")
    store = RuntimeStore(directory)
    store.verify_audit()
    with store.database.transaction(write=False) as c:
        rows = c.execute(
            "SELECT payload FROM monitor_audit WHERE json_extract(payload,'$.kind')=? "
            "ORDER BY sequence DESC LIMIT 100",
            (names[kind],),
        ).fetchall()
    values = [json.loads(row[0])["details"] for row in rows]
    for value in values:
        if (
            kind == "evaluations"
            and value.get("contract_version") == "soc-monitor-offline-trial:v1"
        ):
            if value["evaluation_id"] != content_digest_payload(
                {k: v for k, v in value.items() if k != "evaluation_id"}
            ):
                raise ValueError("STORED_EVALUATION_DIGEST_MISMATCH")
    return display_data(values)
