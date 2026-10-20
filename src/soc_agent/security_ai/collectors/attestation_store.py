"""Bounded session diagnostics bind stream, counter uncertainty and DNS observations."""

import json

from soc_agent.security_ai.collectors.capture_attestation import report
from soc_agent.security_ai.collectors.dns_visibility import diagnose
from soc_agent.security_ai.collectors.finalization import publish
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def summary(c, stream) -> dict:
    attestation = report(c, stream)
    visibility = diagnose(
        stream.dns_stages,
        candidates=stream.port53_metadata_packets if stream.ready else None,
        accepted=stream.dns_count,
        rejected=stream.dns_adapter_rejected,
        missing_response=stream.dns_preprocessing.counts["MISSING_RESPONSE_METADATA"],
    )
    return dict(
        contract="soc-zeek-attestation-dns-summary:v1",
        session_id=str(c.plan.session_id),
        source_digest=c.store.source.source_digest,
        plan_digest=c.plan.identity,
        stream_digest=(c.result or {}).get("stream_sha256"),
        attestation=attestation,
        feature_decisions_digest=(c.preprocessing or {}).get("flow_decisions_digest"),
        quality_gate="NATIVE_BLOCKED_CAPTURE_ATTESTATION_OFFLINE_GATE_UNCHANGED",
        dns_visibility=visibility,
        dns_diagnostic_digest=digest(visibility),
        native_ai="BLOCKED",
        dns9="BLOCKED",
        operational_gate="BLOCKED",
    )


def persist(c) -> dict:
    c.store.verify()
    value = summary(c, c.stream)
    publish(c.directory / "capture-attestation.json", value)
    c.store.runtime.event(
        "ZEEK_CAPTURE_ATTESTATION_DIAGNOSTIC",
        dict(
            summary_digest=digest(value),
            plan_digest=c.plan.identity,
            stream_digest=c.result["stream_sha256"],
            counter_evidence_digest=value["attestation"]["evidence_digest"],
            dns_diagnostic_digest=value["dns_diagnostic_digest"],
            native_ai="BLOCKED",
        ),
    )
    return value


def restore(c) -> dict | None:
    from soc_agent.security_ai.collectors.finalization import Ledger
    from soc_agent.security_ai.collectors.live_stream import Stream, decode
    from soc_agent.security_ai.collectors.offline import file_digest

    c.store.verify()
    with c.store.runtime.database.transaction(write=False) as db:
        rows = [
            json.loads(row[0])["details"]
            for row in db.execute(
                "SELECT payload FROM monitor_audit WHERE "
                "json_extract(payload,'$.kind')='ZEEK_CAPTURE_ATTESTATION_DIAGNOSTIC'"
            )
        ]
    proof = c.directory / "capture-attestation.json"
    if not rows and not proof.exists():
        return None  # Legacy evidence remains unchanged, not retrospectively attested.
    if len(rows) != 1 or c.result.get("plan_digest") != c.plan.identity:
        raise ValueError("ZEEK_ATTESTATION_BINDING_MISMATCH")
    path = c.directory / "stream.jsonl"
    if path.is_symlink() or path.stat().st_size > c.plan.output_bytes:
        raise ValueError("ZEEK_ATTESTATION_BINDING_MISMATCH")
    expected = c.result["stream_sha256"]
    if file_digest(path) != expected:
        raise ValueError("ZEEK_ATTESTATION_BINDING_MISMATCH")
    stream, ledger = Stream(c.store.source), Ledger()
    with path.open("rb") as f:
        while line := f.readline(16385):
            e = decode(line)
            ledger.accept(e, line)
            stream.accept(e)
    if (
        ledger.closed is None
        or stream.sequence != c.result.get("sequence")
        or ledger.closed.model_dump() != c.result.get("closed_detail")
        or file_digest(path) != expected
    ):
        raise ValueError("ZEEK_ATTESTATION_BINDING_MISMATCH")
    value = summary(c, stream)
    if (
        json.loads(read_local(proof, 8192)) != value
        or rows[0].get("summary_digest") != digest(value)
        or rows[0].get("plan_digest") != c.plan.identity
        or rows[0].get("stream_digest") != expected
        or rows[0].get("counter_evidence_digest") != value["attestation"]["evidence_digest"]
        or rows[0].get("dns_diagnostic_digest") != value["dns_diagnostic_digest"]
    ):
        raise ValueError("ZEEK_ATTESTATION_BINDING_MISMATCH")
    return value
