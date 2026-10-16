"""Read-only saved-session verification. No capture, model execution, replay or queue recovery."""

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from soc_agent.linux_runtime.network_monitor import configuration
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.realtime.queue import EventQueue
from soc_agent.security_ai.operational.network_capture.helper_transport import Message
from soc_agent.security_ai.operational.network_capture.live_session import (
    load_session,
    unprivileged,
)
from soc_agent.security_ai.operational.network_capture.models import FlowSummary, PacketObservation
from soc_agent.security_ai.operational.network_capture.pipeline import NetworkPipeline
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt
from soc_agent.security_ai.operational.source_store import OperationalSourceStore
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.live_input import validate_result
from soc_agent.security_ai.research.live_service import LiveResearch, bound_request
from soc_agent.security_ai.research.models import digest, parse_receipt


def hashes(directory):
    return {
        str(p.relative_to(directory)): hashlib.sha256(read_local(p, 64 * 1024**2)).hexdigest()
        for p in directory.rglob("*.sqlite")
    }


def verify(directory: Path) -> dict:
    unprivileged()
    session = load_session(directory)
    before = hashes(directory)
    runtime = directory / "runtime"
    store = RuntimeStore(runtime)
    configured = configuration(runtime, store)
    if configured is None:
        raise ValueError("SAVED_LIVE_NETWORK_NOT_CONFIGURED")
    config, identity = configured
    if identity != session.interface_id or config.interface != "lo":
        raise ValueError("SAVED_LIVE_SOURCE_CONFIGURATION_MISMATCH")
    pipeline = NetworkPipeline(
        EventQueue(runtime / "network/queue.sqlite"),
        OperationalSourceStore(
            runtime / "network/sources.sqlite",
            allowed_lateness_seconds=60,
            max_future_skew_seconds=5,
            capacity=10000,
        ),
        store.config.incident_id,
        config,
        identity,
        store,
    )
    projection = SimpleNamespace(pipeline=pipeline, store=store, config=config)
    packets, flows = [], {}
    with pipeline.queue.database.transaction(write=False) as c:
        for row in c.execute("SELECT * FROM realtime_events ORDER BY rowid"):
            event = pipeline.queue._decode(row)
            record = pipeline.decode(event)
            if event.source.generation != str(session.session_id):
                raise ValueError("SAVED_LIVE_EVENT_SESSION_MISMATCH")
            source = pipeline._source(event, record)
            receipt = build_receipt(
                pipeline.sources, incident_id=pipeline.incident, sources=(source,)
            )
            verify_receipt(
                receipt, pipeline.sources, incident_id=pipeline.incident, sources=(source,)
            )
            if pipeline.committed.get(str(event.event_id)) != receipt.model_dump(mode="json"):
                raise ValueError("SAVED_LIVE_SOURCE_AUDIT_MISMATCH")
            if isinstance(record, PacketObservation):
                packets.append(record)
            elif isinstance(record, FlowSummary):
                flows[record.flow_id] = (event, record)
    research = LiveResearch(directory).snapshot()
    model_receipts = []
    for record in research["records"]:
        if record.get("receipt"):
            receipt = parse_receipt(record["receipt"])
            event, flow = flows[receipt.flow_id]
            request = bound_request(projection, session.session_id, event, flow, receipt.profile)
            request = request.model_copy(update={"invocation_id": receipt.invocation_id})
            validate_result(request, receipt)
            model_receipts.append(
                {
                    k: record["receipt"][k]
                    for k in (
                        "profile",
                        "origin",
                        "artifact_digest",
                        "feature_digest",
                        "source_digest",
                        "provenance_digest",
                        "score",
                        "prediction",
                        "inference_latency_ms",
                        "worker_peak_rss_bytes",
                        "worker_cpu_seconds",
                        "validation_level",
                    )
                }
                | {
                    "receipt_digest": digest(record["receipt"]),
                    "investigation_status": (record.get("investigation") or {}).get(
                        "status", "UNKNOWN"
                    ),
                }
            )
    ready = Message.model_validate_json(read_local(directory / "verified-ready.json", 8192))
    closed = Message.model_validate_json(read_local(directory / "verified-closed.json", 8192))
    with store.database.transaction(write=False) as c:
        audit_records = [json.loads(r[0]) for r in c.execute("SELECT payload FROM monitor_audit")]
    if not any(
        r["kind"] == "LIVE_HELPER_VERIFIED"
        and r["details"]
        == {
            "session_digest": digest(session.model_dump(mode="json")),
            "ready_digest": digest(ready.model_dump(mode="json")),
        }
        for r in audit_records
    ) or not any(
        r["kind"] == "LIVE_HELPER_CLOSED"
        and r["details"]["terminal_digest"] == digest(closed.model_dump(mode="json"))
        for r in audit_records
    ):
        raise ValueError("SAVED_HELPER_RECEIPT_AUDIT_MISMATCH")
    integrity = {}
    for relative in before:
        with sqlite3.connect((directory / relative).as_uri() + "?mode=ro", uri=True) as c:
            integrity[relative] = c.execute("PRAGMA integrity_check").fetchone()[0]
    after = hashes(directory)
    if before != after or set(integrity.values()) != {"ok"}:
        raise ValueError("SAVED_LIVE_DATABASE_INTEGRITY_MISMATCH")
    cap = ready.capabilities
    passed = (
        bool(packets)
        and all(p.timestamp_origin == "KERNEL_SO_TIMESTAMPNS" for p in packets)
        and ready.session_id == closed.session_id == session.session_id
        and cap == closed.capabilities
        and all(cap[k] == 0 for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
        and cap["NoNewPrivs"] == 1
        and cap["CapBnd"] == 8192
        and closed.error is None
        and closed.capture_drops == 0
        and closed.received_frames <= session.max_packets
        and closed.elapsed_seconds <= session.seconds
        and {r["profile"] for r in model_receipts} == {"quality", "edge"}
        and all(
            r["origin"] == "NATIVE_AF_PACKET" and r["investigation_status"] == "ASSESSED_READ_ONLY"
            for r in model_receipts
        )
        and pipeline.queue.counts() == {"DONE": len(packets) + len(flows)}
    )
    return {
        "status": "VERIFIED" if passed else "PARTIAL",
        "session_id": str(session.session_id),
        "packets": len(packets),
        "flows": len(flows),
        "models": model_receipts,
        "queue": pipeline.queue.counts(),
        "audit_digest": store.verify_audit(),
        "research_audit": research["audit_integrity"],
        "capabilities": cap,
        "elapsed_seconds": closed.elapsed_seconds,
        "capture_drops": closed.capture_drops,
        "capture_gap_count": store.state().get("network", {}).get("gap_count"),
        "sqlite_integrity": integrity,
        "database_sha256": before,
        "database_unchanged": True,
        "operational_gate": "OPERATIONAL_INFERENCE_BLOCKED",
        "operational_input": "NOT_INFERABLE",
        "action_policy": "WRITE_DENIED",
        "source_assurance": "LOCAL_CHAIN_NOT_REMOTE_ATTESTATION",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.directory.absolute())
    except (OSError, ValueError, KeyError, sqlite3.Error):
        result = {"status": "BLOCKED", "reason": "SAVED_LIVE_EVIDENCE_MISSING_OR_INVALID"}
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
