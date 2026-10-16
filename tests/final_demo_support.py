"""Test/evidence utilities only. No collector, model loader or Runtime implementation."""

import hashlib
import json
import re
import sqlite3
import struct
from pathlib import Path
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from soc_agent.gui.queries import investigation_rows, stored_counts
from soc_agent.linux_runtime.__main__ import status
from soc_agent.security_ai.external.runtime_store import validate_audit
from soc_agent.security_ai.research.models import SPECS, digest, parse_receipt

NETWORK_CONTRACT = "84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e"
DNS_CONTRACT = "3276c1b595ec566677bce530f2839247b7fa1320dc5e3549f85c0c17c959edd0"
DNS_ARTIFACT = "28e089af363dd565a4fb3d3f202de9e9f9804bd14a164de4fd7b61adb1201e33"


def file_sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def database_hashes(directory: Path) -> dict[str, str]:
    return {p.name: file_sha(p) for p in sorted(directory.glob("*.sqlite"))}


def audit_state(path: Path) -> dict:
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as c:
        c.row_factory = sqlite3.Row
        validate_audit(c)
        integrity = c.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        head = c.execute(
            "SELECT digest FROM external_security_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return {
            "integrity": "VERIFIED",
            "sqlite_integrity": integrity,
            "digest": head[0] if head else "UNKNOWN",
            "events": c.execute("SELECT COUNT(*) FROM external_security_audit").fetchone()[0],
        }


def retained_authentication(directory: Path) -> dict:
    before = database_hashes(directory)
    assert len(before) == 4, "Expected the existing complete retained Authentication workspace"
    runtime, counts, rows = (
        status(directory),
        stored_counts(directory),
        investigation_rows(directory),
    )
    assert runtime["runtime_state"] == "STOPPED" and rows
    assert all(r["origin"] == "NATIVE_OS" for r in rows)
    integrity = {}
    for p in directory.glob("*.sqlite"):
        with sqlite3.connect(p.as_uri() + "?mode=ro", uri=True) as c:
            integrity[p.name] = c.execute("PRAGMA integrity_check").fetchone()[0]
    assert set(integrity.values()) == {"ok"}
    with sqlite3.connect((directory / "monitor.sqlite").as_uri() + "?mode=ro", uri=True) as c:
        audit_head = c.execute(
            "SELECT digest FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0]
    with sqlite3.connect((directory / "sources.sqlite").as_uri() + "?mode=ro", uri=True) as c:
        sources = []
        for payload, source_digest in c.execute(
            "SELECT payload,digest FROM operational_sources WHERE status='ACCEPTED' "
            "AND json_extract(payload,'$.kind')='authentication'"
        ):
            header = json.loads(payload)["header"]
            sources.append(
                {
                    "event_identity_digest": digest(header["event_id"]),
                    "event_timestamp": header["observed_at"],
                    "source_identity_digest": digest(header["source"]),
                    "source_digest": source_digest,
                }
            )
        windows = c.execute("SELECT COUNT(*) FROM operational_auth_windows").fetchone()[0]
    findings = []
    for row in rows:
        provenance = row["provenance"]
        findings.append(
            {
                "finding_id": row["finding_id"],
                "incident_id": row["incident_id"],
                "origin": row["origin"],
                "status": row["status"],
                "event_timestamp": row["observations"]["first_seen"],
                "evidence_references": row["evidence_references"],
                "provenance_digest": digest(provenance),
                "investigation_reference": row["investigation_reference"] or "UNKNOWN",
                "audit_reference_digest": digest(row["audit_reference"]),
            }
        )
    assert database_hashes(directory) == before
    return {
        "input_origin": "RETAINED_NATIVE_OS",
        "runtime_state": runtime["runtime_state"],
        "health": runtime["health"],
        "readiness": runtime["readiness"],
        "collector_checkpoint": runtime["collector_state"],
        "queue_backlog": runtime["queue_backlog"],
        "retained_queue_records": counts["collected_events"],
        "authentication_events": counts["authentication_events"],
        "sources": sources,
        "authentication_windows": windows,
        "findings": findings,
        "audit_integrity": runtime["audit_store_health"],
        "audit_digest": audit_head,
        "sqlite_integrity": integrity,
        "database_sha256_before": before,
        "database_sha256_after": before,
        "database_unchanged": True,
        "new_journal_collection": False,
        "operational_inference": runtime["inference_status"],
        "action_policy": runtime["write_disposition"],
    }


def invocation_summary(record: dict) -> dict:
    r, inv = record["receipt"], record["investigation"]
    parse_receipt(r)
    assert record["status"] == "COMPLETE" and inv["status"] == "ASSESSED_READ_ONLY"
    assert inv["checkpoint_restored"] and inv["provider_calls"] == 0
    assert inv["action_policy"] == "WRITE_DENIED"
    assert inv["context"]["receipt_digest"] == digest(r)
    assert inv["context"]["role"] == "UNTRUSTED_MODEL_INFERENCE_NOT_EVIDENCE"
    assert not inv["assessment"]["incident_state"]["observations"]
    assert not inv["assessment"]["incident_state"]["hypotheses"]
    dns = r["profile"] == "dns"
    return {
        "invocation_id": r["invocation_id"],
        "model_identity": r["model_id"],
        "profile": r["profile"],
        "artifact_sha256": r["artifact_digest"],
        "model_manifest_digest": r.get("model_manifest_digest", "UNKNOWN"),
        "input_origin": r["origin"],
        "input_digest": r["input_digest"] if dns else digest(r["feature_values"]),
        "source_identity": r["fixture_id"] if dns else r["source_digest"],
        "source_file_sha256": "UNKNOWN" if dns else r["source_sha256"],
        "feature_digest": "UNKNOWN" if dns else r["feature_digest"],
        "feature_contract_digest": r["feature_contract_digest"] if dns else NETWORK_CONTRACT,
        "feature_order_digest": digest(r["feature_names"]),
        "producer_version": "UNKNOWN" if dns else r["producer_version"],
        "validation_level": r["validation_level"] if dns else "OFFLINE_VERIFIED_FLOW",
        "score": r["score"],
        "threshold": r["threshold"],
        "prediction": r["prediction"],
        "inferred_at": r["inferred_at"],
        "inference_latency_ms": r["inference_latency_ms"],
        "inference_receipt_digest": digest(r),
        "completed_record_digest": digest(record),
        "incident_id": inv["incident_id"],
        "investigation_status": inv["status"],
        "context_digest": inv["context_digest"],
        "evidence_references": inv["evidence_references"],
        "checkpoint_restored": inv["checkpoint_restored"],
        "provider_calls": inv["provider_calls"],
        "status": r["status"],
        "operational_gate": r["operational_inference"],
        "action_policy": r["write_policy"],
        "calibration": r["calibration"],
    }


def screenshot_entry(path: Path) -> dict:
    width, height = struct.unpack(">II", path.read_bytes()[16:24])
    return {
        "filename": "screenshots/" + path.name,
        "sha256": file_sha(path),
        "width": width,
        "height": height,
        "source": "ACTUAL_WSLG_WINDOW",
    }


class Checked(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, hide_input_in_errors=True)


class ImageEvidence(Checked):
    filename: str = Field(pattern=r"^screenshots/[a-z0-9-]+\.png$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    width: int = Field(ge=640, le=4096)
    height: int = Field(ge=480, le=2160)
    source: Literal["ACTUAL_WSLG_WINDOW"]


class FinalManifest(Checked):
    contract: Literal["soc-final-demo-evidence:v1"]
    run_id: UUID
    validation_date: str
    soc_head: str = Field(pattern=r"^[a-f0-9]{40}$")
    ml_head: str = Field(pattern=r"^[a-f0-9]{40}$")
    environment: dict
    launch: dict
    initial_gui: dict
    invocations: list[dict] = Field(min_length=6, max_length=6)
    authentication: dict
    audit: dict
    recovery: dict
    screenshots: list[ImageEvidence] = Field(min_length=18, max_length=40)
    runtime_state: Literal["STOPPED"]
    operational_gate: Literal["BLOCKED"]
    validation_result: Literal["VERIFIED"]
    known_limitations: list[str] = Field(default_factory=list)
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def bindings(self) -> Self:
        raw = self.model_dump(mode="json", exclude_unset=True)
        if digest({k: v for k, v in raw.items() if k != "manifest_digest"}) != self.manifest_digest:
            raise ValueError("MANIFEST_DIGEST_MISMATCH")
        rows = self.invocations
        if (
            len({r["invocation_id"] for r in rows}) != 6
            or len({r["incident_id"] for r in rows}) != 6
        ):
            raise ValueError("DUPLICATE_OR_MERGED_INVESTIGATION")
        for profile in ("quality", "edge", "dns"):
            if sum(r["profile"] == profile for r in rows) != 2:
                raise ValueError("MODEL_COVERAGE_MISMATCH")
        for r in rows:
            required = {
                "profile",
                "input_origin",
                "artifact_sha256",
                "feature_contract_digest",
                "status",
                "operational_gate",
                "action_policy",
                "investigation_status",
                "checkpoint_restored",
                "provider_calls",
                "model_identity",
                "threshold",
                "score",
                "prediction",
                "input_digest",
                "inference_receipt_digest",
            }
            if not required <= r.keys():
                raise ValueError("MISSING_INVOCATION_EVIDENCE")
            dns = r["profile"] == "dns"
            if (
                r["input_origin"] != ("FIXTURE" if dns else "OFFLINE_PCAP")
                or r["artifact_sha256"] != (DNS_ARTIFACT if dns else SPECS[r["profile"]]["sha256"])
                or r["feature_contract_digest"] != (DNS_CONTRACT if dns else NETWORK_CONTRACT)
                or r["status"] != "RESEARCH_ONLY"
                or r["operational_gate"] != "BLOCKED"
                or r["action_policy"] != "WRITE_DENIED"
                or r["investigation_status"] != "ASSESSED_READ_ONLY"
                or r["checkpoint_restored"] is not True
                or r["provider_calls"] != 0
                or r["model_identity"]
                != ("dns_cicbell_dnn_int8" if dns else SPECS[r["profile"]]["model_id"])
                or r["threshold"] != (0.5 if dns else SPECS[r["profile"]]["threshold"])
                or type(r["score"]) not in (float, int)
                or not 0 <= r["score"] <= 1
                or r["prediction"] != ("CLASS_1" if r["score"] >= r["threshold"] else "CLASS_0")
            ):
                raise ValueError("RESEARCH_BOUNDARY_MISMATCH")
        a, recovery = self.authentication, self.recovery
        if {r["incident_id"] for r in a["findings"]} & {r["incident_id"] for r in rows}:
            raise ValueError("CROSS_DOMAIN_INCIDENT_MERGE")
        if (
            a["input_origin"] != "RETAINED_NATIVE_OS"
            or a["runtime_state"] != "STOPPED"
            or a["new_journal_collection"] is not False
            or a["database_unchanged"] is not True
            or a["database_sha256_before"] != a["database_sha256_after"]
            or set(a["sqlite_integrity"].values()) != {"ok"}
            or recovery["new_inferences_after_cached_replay"] != 0
            or recovery["worker_running"] is not False
            or recovery["demo_state"] != "STOPPED"
            or recovery["same_invocation_ids"] is not True
            or recovery["same_audit_head"] is not True
            or recovery["process_boundary"] != "NEW_PYTHON_PROCESS"
            or self.audit["integrity"] != "VERIFIED"
        ):
            raise ValueError("READ_ONLY_OR_RECOVERY_MISMATCH")
        if len({s.filename for s in self.screenshots}) != len(self.screenshots):
            raise ValueError("DUPLICATE_SCREENSHOT")
        for view in (
            "dashboard-initial",
            "network-quality",
            "network-edge",
            "dns-security",
            "authentication",
            "investigation",
            "audit",
            "runtime-recovery",
            "unified-dashboard",
        ):
            for width in (1920, 1366):
                if not any(
                    s.filename == f"screenshots/{view}-{width}.png" for s in self.screenshots
                ):
                    raise ValueError("SCREENSHOT_COVERAGE_MISSING")
        _public_only(raw)
        return self


def _public_only(value: object) -> None:
    if isinstance(value, dict):
        forbidden = {
            "password",
            "token",
            "credential",
            "api_key",
            "raw_data",
            "raw_payload",
            "username",
            "hostname",
        }
        if any(str(k).lower() in forbidden for k in value):
            raise ValueError("PRIVATE_EVIDENCE_FIELD")
        for item in value.values():
            _public_only(item)
    elif isinstance(value, list):
        for item in value:
            _public_only(item)
    elif isinstance(value, str) and (
        "/home/" in value
        or re.search(r"(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{25,})", value)
    ):
        raise ValueError("PRIVATE_EVIDENCE_VALUE")


def verify_manifest(value: dict, directory: Path) -> FinalManifest:
    result = FinalManifest.model_validate(value)
    if (directory / "screenshots").is_symlink():
        raise ValueError("UNSAFE_SCREENSHOT_ROOT")
    for image in result.screenshots:
        path = directory / image.filename
        if path.is_symlink() or path.resolve().parent != (directory / "screenshots").resolve():
            raise ValueError("UNSAFE_SCREENSHOT_PATH")
        if not 24 <= path.stat().st_size <= 8 * 1024 * 1024:
            raise ValueError("SCREENSHOT_SIZE")
        raw = path.read_bytes()
        if (
            raw[:8] != b"\x89PNG\r\n\x1a\n"
            or struct.unpack(">II", raw[16:24]) != (image.width, image.height)
            or file_sha(path) != image.sha256
        ):
            raise ValueError("SCREENSHOT_DIGEST_OR_DIMENSION_MISMATCH")
    return result
