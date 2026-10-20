"""Append-only bound preprocessing summaries, never replay or resume inference."""

import json

from soc_agent.security_ai.collectors.finalization import publish
from soc_agent.security_ai.collectors.preprocessing import final_summary
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import digest


def persist(collector) -> dict:
    c = collector
    c.store.verify()
    value = final_summary(c, c.stream)
    publish(c.directory / "preprocessing-proof.json", value)
    c.store.runtime.event(
        "ZEEK_PREPROCESSING_FINALIZED",
        dict(
            summary_digest=digest(value),
            plan_digest=c.plan.identity,
            stream_digest=c.result["stream_sha256"],
            flow_decisions_digest=value["flow_decisions_digest"],
            native_ai="BLOCKED",
        ),
    )
    return value


def restore(collector) -> dict | None:
    from soc_agent.security_ai.collectors.finalization import Ledger
    from soc_agent.security_ai.collectors.live_stream import Stream, decode
    from soc_agent.security_ai.collectors.offline import file_digest

    c = collector
    c.store.verify()
    with c.store.runtime.database.transaction(write=False) as db:
        rows = [
            json.loads(row[0])["details"]
            for row in db.execute(
                "SELECT payload FROM monitor_audit WHERE "
                "json_extract(payload,'$.kind')='ZEEK_PREPROCESSING_FINALIZED'"
            )
        ]
    proof = c.directory / "preprocessing-proof.json"
    if not rows and not proof.exists():
        return None  # Legacy evidence remains unchanged; no invented normalization proof.
    if len(rows) != 1 or c.result.get("plan_digest") != c.plan.identity:
        raise ValueError("ZEEK_PREPROCESSING_PROOF_MISMATCH")
    path = c.directory / "stream.jsonl"
    if (
        path.is_symlink()
        or path.stat().st_size > c.plan.output_bytes
        or file_digest(path) != c.result["stream_sha256"]
    ):
        raise ValueError("ZEEK_PREPROCESSING_PROOF_MISMATCH")
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
    ):
        raise ValueError("ZEEK_PREPROCESSING_PROOF_MISMATCH")
    value = final_summary(c, stream)
    if (
        json.loads(read_local(proof, 8192)) != value
        or rows[0].get("summary_digest") != digest(value)
        or rows[0].get("plan_digest") != c.plan.identity
        or rows[0].get("stream_digest") != c.result["stream_sha256"]
        or rows[0].get("flow_decisions_digest") != value["flow_decisions_digest"]
    ):
        raise ValueError("ZEEK_PREPROCESSING_PROOF_MISMATCH")
    return value
