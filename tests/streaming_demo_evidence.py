"""Actual RF/LR in explicit synthetic managed streaming mode. Never native evidence."""

import argparse
import asyncio
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import tests.native_capture_verification_guard as guard
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import idle_source


async def collect(directory: Path):
    owner = StreamingMonitoring(directory, paths=research_paths())
    await owner.start_fixture(idle_source(owner), policy=StreamPolicy(seconds=120))
    await asyncio.wait_for(owner.task, 45)
    snapshot = owner.snapshot()
    records = snapshot["research"]["records"]
    assert len(records) == 2 and all(r["status"] == "COMPLETE" for r in records)
    assert owner.metrics["inference_count"] == 2
    integrity = []
    for file in owner.directory.rglob("*.sqlite"):
        with sqlite3.connect(file.as_uri() + "?mode=ro", uri=True) as c:
            integrity.append(c.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
    restored = StreamingMonitoring(directory, paths=research_paths())
    recovery = await restored.restore_latest()
    assert recovery["research"]["records"] == records
    assert not recovery["collection_live"] and not recovery["research"]["worker_running"]
    assert recovery["network"]["current_inference_count"] == 0
    assert guard.blocked == 0
    return dict(
        contract="soc-managed-stream-fixture-evidence:v1",
        run_id=str(uuid4()),
        validated_at=datetime.now(UTC).isoformat(),
        validation="ACTUAL_MODELS_SYNTHETIC_PACKET_FIXTURE_NOT_NATIVE_CAPTURE",
        network_origin="FIXTURE",
        raw_capture_performed=False,
        source_commit_count=sum(owner.store.queue.counts().values()),
        queue=owner.store.queue.counts(),
        packet_count=owner.metrics["packets_collected"],
        eligible_flow_count=owner.eligible,
        excluded_flow_count=owner.excluded,
        finalization=owner.metrics["finalization"],
        sqlite_integrity=all(integrity),
        audit_digest=owner.store.runtime.verify_audit(),
        inference_count=owner.metrics["inference_count"],
        receipts=[
            dict(
                receipt=r["receipt"],
                receipt_digest=digest(r["receipt"]),
                investigation_id=r["investigation"]["incident_id"],
                investigation_digest=digest(r["investigation"]),
                checkpoint_restored=r["investigation"]["checkpoint_restored"],
                write_policy=r["investigation"]["action_policy"],
            )
            for r in records
        ],
        recovery_state=recovery["state"],
        restart_new_inference_count=0,
        transient_input_files=len(list((owner.directory / "inputs").glob("*"))),
        active_metadata_bytes=owner.aggregator.bytes,
        helper_sha256=hashlib.sha256(
            Path(
                "src/soc_agent/security_ai/operational/network_capture/stream_helper.py"
            ).read_bytes()
        ).hexdigest(),
        operational_gate=snapshot["operational_gate"],
        write_policy=snapshot["write_policy"],
        native_continuous_capture="PENDING_USER_APPROVAL",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = asyncio.run(collect(args.directory))
    with args.output.open("x") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "run_id",
                    "inference_count",
                    "finalization",
                    "operational_gate",
                    "native_continuous_capture",
                )
            }
        )
    )
