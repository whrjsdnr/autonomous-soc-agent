"""Bounded Native diagnostic summary, bound to existing source/stream/audit evidence."""

import json
from collections import Counter

from soc_agent.security_ai.collectors.finalization import Ledger, publish
from soc_agent.security_ai.collectors.integrity import (
    FlowReport,
    SessionReport,
    assess_session,
    eligibility,
    validate_flow,
)
from soc_agent.security_ai.collectors.live_stream import Stream, decode
from soc_agent.security_ai.collectors.offline import file_digest
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def summary(plan, stream, result, *, queue_depth=0, failed=False) -> dict:
    flows = tuple(validate_flow(f, plan.session_id) for f in stream.finalized)
    report = assess_session(
        plan.session_id,
        plan.identity,
        result,
        protocol_verified=bool(stream.closed and stream.closed_detail),
        queue_depth=queue_depth,
        flows=flows,
        failed=failed,
        port53_metadata_packets=stream.port53_metadata_packets,
    )
    unknown = FlowReport(
        feature_integrity="NOT_OBSERVED", completeness="NOT_OBSERVED", reason="NO_FLOW"
    )
    decisions = tuple(
        eligibility(report, f, parity="UNVERIFIED", artifact="NOT_OBSERVED") for f in flows
    )
    decision = eligibility(
        report, flows[0] if flows else unknown, parity="UNVERIFIED", artifact="NOT_OBSERVED"
    )
    return dict(
        contract="soc-zeek-native-integrity-summary:v1",
        collector=dict(
            image=plan.image,
            bundle_digest=plan.bundle_digest,
            interface=plan.interface,
            generation=str(plan.controller_generation),
        ),
        session=report.model_dump(mode="json"),
        flow_count=len(flows),
        feature_metadata_verified=sum(f.feature_integrity == "VERIFIED" for f in flows),
        timeout_complete_flows=sum(f.completeness == "VERIFIED" for f in flows),
        flow_reasons=dict(Counter(f.reason for f in flows)),
        flow_decisions_digest=digest(
            [
                dict(flow=f.model_dump(mode="json"), eligibility=d.model_dump(mode="json"))
                for f, d in zip(flows, decisions, strict=True)
            ]
        ),
        ai_decision=decision.model_dump(mode="json"),
        source_packet_digest=result.get("stream_sha256"),
        native_inference="BLOCKED",
        dns9="BLOCKED",
        operational_gate="BLOCKED",
        scope="STORED_METADATA_ARITHMETIC_NOT_RAW_PACKET_PARITY_OR_CAPTURE_ATTESTATION",
        policy_changes=False,
    )


def persist(collector) -> dict:
    c = collector
    c.store.verify()
    value = summary(c.plan, c.stream, c.result, queue_depth=c.queue_depth)
    publish(c.directory / "native-integrity.json", value)
    c.store.runtime.event(
        "ZEEK_NATIVE_INTEGRITY_ASSESSED",
        dict(
            summary_digest=digest(value),
            plan_digest=c.plan.identity,
            stream_digest=c.result["stream_sha256"],
            capture=value["session"]["capture"],
            native_inference="BLOCKED",
        ),
    )
    return value


def restore(collector) -> dict:
    """Reverify the bounded stream and audit binding; never persist, capture or infer."""
    c = collector
    c.store.verify()
    rows = []
    with c.store.runtime.database.transaction(write=False) as db:
        for row in db.execute(
            "SELECT payload FROM monitor_audit WHERE "
            "json_extract(payload,'$.kind')='ZEEK_NATIVE_INTEGRITY_ASSESSED'"
        ):
            rows.append(json.loads(row[0])["details"])
    if c.result.get("plan_digest") != c.plan.identity:
        raise ValueError("ZEEK_NATIVE_INTEGRITY_PROOF_MISMATCH")
    path = c.directory / "stream.jsonl"
    if (
        path.is_symlink()
        or path.stat().st_size > c.plan.output_bytes
        or file_digest(path) != c.result["stream_sha256"]
    ):
        raise ValueError("ZEEK_NATIVE_INTEGRITY_PROOF_MISMATCH")
    ledger, stream = Ledger(), Stream(c.store.source)
    with path.open("rb") as f:
        while line := f.readline(16385):
            envelope = decode(line)
            ledger.accept(envelope, line)
            stream.accept(envelope)
    if (
        ledger.closed is None
        or stream.sequence != c.result.get("sequence")
        or ledger.closed.model_dump() != c.result.get("closed_detail")
    ):
        raise ValueError("ZEEK_NATIVE_INTEGRITY_PROOF_MISMATCH")
    value = summary(c.plan, stream, c.result)
    certificate = c.directory / "native-integrity.json"
    if rows or certificate.exists():
        stored = json.loads(read_local(certificate, 8192))
        if (
            stored != value
            or len(rows) != 1
            or rows[0].get("summary_digest") != digest(value)
            or rows[0].get("plan_digest") != c.plan.identity
            or rows[0].get("stream_digest") != c.result["stream_sha256"]
        ):
            raise ValueError("ZEEK_NATIVE_INTEGRITY_PROOF_MISMATCH")
    # Old sessions without this diagnostic proof may be projected, not upgraded.
    # No new file or Audit event is written during restore.
    return value


def report_from(value: dict) -> SessionReport:
    return SessionReport.model_validate(value["session"])
