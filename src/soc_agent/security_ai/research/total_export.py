"""Explicit local, bounded redacted exports; never sends data externally."""

import json
import os
from pathlib import Path

from soc_agent.security_ai.research.models import digest


def document(owner):
    snapshot = owner.snapshot()
    if snapshot["runtime_audit_integrity"] != "VERIFIED":
        raise ValueError("TOTAL_EXPORT_AUDIT_REQUIRED")
    records = []
    for record in snapshot["research"].get("records", []):
        receipt = record.get("receipt") or {}
        investigation = record.get("investigation") or {}
        records.append(
            {
                "event_identity": receipt.get("flow_id"),
                "input_origin": receipt.get("origin"),
                "model_receipt": {
                    key: receipt.get(key)
                    for key in (
                        "model_id",
                        "profile",
                        "artifact_digest",
                        "producer_version",
                        "feature_contract_digest",
                        "producer_configuration_digest",
                        "source_digest",
                        "capture_session",
                        "flow_id",
                        "feature_digest",
                        "prediction",
                        "score",
                        "threshold",
                        "inferred_at",
                        "provenance_digest",
                        "inference_latency_ms",
                        "worker_peak_rss_bytes",
                        "worker_cpu_seconds",
                    )
                },
                "receipt_digest": digest(receipt),
                "risk_assessment": investigation.get("assessment"),
                "assessment_assurance": "SCRIPTED_READ_ONLY_RESEARCH_NOT_OPERATIONAL",
                "investigation_summary": {
                    key: investigation.get(key)
                    for key in (
                        "incident_id",
                        "status",
                        "mode",
                        "action_policy",
                        "checkpoint_restored",
                        "evidence_references",
                        "context_digest",
                    )
                },
                "score_meaning": "UNCALIBRATED_RESEARCH_SCORE_NOT_CONFIRMED_ATTACK",
            }
        )
    return {
        "contract": "soc-total-export:v1",
        "research_status": "RESEARCH_ONLY",
        "capture_session": snapshot["session_id"],
        "input_origin": snapshot["input_origin"],
        "runtime_state": snapshot["state"],
        "finalization": snapshot["network"].get("finalization"),
        "audit_digest": owner.store.runtime.verify_audit(),
        "records": records,
        "dns": snapshot["dns"],
        "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
        "write_policy": "WRITE_DENIED",
        "validation": "FIXTURE_ONLY" if owner.fixture else "NATIVE_LOCAL_EVIDENCE",
    }


def export(owner, path: Path, format: str):
    if format not in ("json", "markdown"):
        raise ValueError("TOTAL_EXPORT_FORMAT_INVALID")
    value = document(owner)
    body = json.dumps(value, sort_keys=True, indent=2, allow_nan=False)
    if format == "markdown":
        body = (
            "# SOC Total Monitoring Report\n\nRESEARCH_ONLY · WRITE_DENIED\n\n```json\n"
            + body
            + "\n```\n"
        )
    encoded = body.encode()
    if len(encoded) > 1024**2:
        raise ValueError("TOTAL_EXPORT_SIZE_LIMIT")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        path.unlink(missing_ok=True)
        raise
    return {
        "status": "EXPORTED_LOCAL_ONLY",
        "bytes": len(encoded),
        "document_digest": digest(value),
    }
