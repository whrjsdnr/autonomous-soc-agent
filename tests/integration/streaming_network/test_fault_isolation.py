"""Offline fixtures; real artifacts only where stated, never Native authorization."""

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from tests.research_adapter_support import research_paths
from tests.streaming_network_support import packet
from tests.total_monitoring_support import dns_packet

from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.research.stream_service import StreamingMonitoring
from soc_agent.security_ai.research.total_export import document


async def independent_source(owner):
    # Healthy flow A, independent corrupted B, and a separate DNS conversation.
    yield packet(owner, 0)
    yield packet(owner, 0.5, reverse=True, flags=16, length=60)
    yield packet(owner, 1, flags=1, length=80)
    yield packet(owner, 2, port=3000)
    yield packet(owner, 3, port=3000)
    yield packet(owner, 2.999989, port=3000)  # Fixture datetime has microsecond precision.
    yield dns_packet(owner, 4)
    yield dns_packet(owner, 4.5, response=True)
    yield dns_packet(owner, 4.6, malformed=True)
    yield packet(owner, 31)  # Same-key 30s idle evidence, not a foreign watermark.


@pytest.mark.asyncio
async def test_quarantine_dns_actual_models_integrity_receipts_and_recovery(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    await owner.start_fixture(independent_source(owner))
    await asyncio.wait_for(owner.task, 30)
    snapshot = owner.snapshot()
    assert owner.last_error is None
    assert snapshot["network"]["inference_count"] == 2
    assert snapshot["network"]["quarantined_flow_count"] == 1
    assert snapshot["network"]["retained_integrity_health"] == "DEGRADED"
    assert snapshot["network"]["retained_metadata_bytes"] == 0
    assert snapshot["dns"]["counts"]["MATCHED_RESPONSE"] == 1
    assert snapshot["dns"]["counts"]["PARSE_FAILURE"] == 1
    assert snapshot["dns"]["dns9_inference"] == "BLOCKED"
    records = snapshot["research"]["records"]
    assert {r["receipt"]["profile"] for r in records} == {"quality", "edge"}
    for row in records:
        assert row["receipt"]["origin"] == "FIXTURE"
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        proof = row["integrity_receipt"]
        assert proof["model_receipt_digest"] == digest(row["receipt"])
        assert proof["feature_digest"] == row["receipt"]["feature_digest"]
        assert proof["integrity_status"] == row["integrity_status_current"] == "FLOW_LOCAL_VERIFIED"
        assert proof["quarantine_reference"] is None
        assert proof["capture_integrity"] == "FIXTURE_NO_CAPTURE"
    exported = document(owner)
    assert exported["flow_integrity"]["quarantined_flow_keys"] == 1
    assert exported["records"][0]["integrity_receipt"]
    audit = owner.store.runtime.verify_audit()
    saved = [digest(row["receipt"]) for row in records]
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    recovered = await restored.restore_latest()
    assert recovered["network"]["integrity_state"] == "RECOVERY_PENDING"
    assert recovered["network"]["quarantined_flow_count"] == 1
    assert recovered["network"]["inference_count"] == 0
    assert not recovered["collection_live"]
    assert [digest(r["receipt"]) for r in recovered["research"]["records"]] == saved
    assert audit != restored.store.runtime.verify_audit()  # Recovery appended, did not rewrite.
    assert recovered["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    output = os.getenv("SOC_ISOLATION_EVIDENCE_OUTPUT")
    if output:
        evidence = dict(
            validation="ACTUAL_RF_LR_ON_SYNTHETIC_FIXTURE_NOT_NATIVE",
            result=document(owner),
            recovered_inference_count=recovered["network"]["inference_count"],
            recovered_quarantines=recovered["network"]["quarantined_flow_count"],
        )
        with Path(output).open("x") as stream:
            json.dump(dict(evidence=evidence, evidence_digest=digest(evidence)), stream, indent=2)


@pytest.mark.asyncio
async def test_late_quarantine_withdraws_retained_advisory_without_rewriting_receipts(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    receipt_files = {}

    async def source():
        for t in (0, 0.5, 1, 31):
            yield packet(owner, t, reverse=t == 0.5)
        for _ in range(1000):
            if owner.metrics["inference_count"] == 2:
                break
            await asyncio.sleep(0.02)
        assert owner.metrics["inference_count"] == 2
        receipt_files.update(
            {p.name: p.read_bytes() for p in owner.demo.directory.glob("receipt-*")}
        )
        yield packet(owner, 1)  # Same key regresses after a prior valid prefix receipt.
        yield packet(owner, 70)  # Key tombstone forbids reuse / another inference.

    await owner.start_fixture(source())
    await asyncio.wait_for(owner.task, 30)
    rows = owner.snapshot()["research"]["records"]
    assert len(rows) == 2 and owner.metrics["inference_count"] == 2
    assert all(r["integrity_status_current"] == "QUARANTINED_FLOW" for r in rows)
    assert all(r["advisory_current"] == "WITHDRAWN_RESEARCH_ONLY" for r in rows)
    assert all(r["quarantine_reference"] for r in rows)
    for name, body in receipt_files.items():
        assert (owner.demo.directory / name).read_bytes() == body
    assert all(r["risk_assessment"] is None for r in document(owner)["records"])
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    recovered = await restored.restore_latest()
    assert all(
        r["advisory_current"] == "WITHDRAWN_RESEARCH_ONLY" for r in recovered["research"]["records"]
    )
    assert recovered["network"]["inference_count"] == 0


@pytest.mark.asyncio
async def test_parity_failure_is_flow_local_and_other_key_still_runs_real_models(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    original = None
    first = None

    def inconsistent(request, receipt):
        nonlocal first
        first = first or request.flow_id
        if request.flow_id == first:
            owner.demo.expected_values = tuple(v + 1 for v in owner.demo.expected_values)
        original(request, receipt)

    async def source():
        yield packet(owner, 0, port=3000)
        yield packet(owner, 1, port=3000)
        yield packet(owner, 31, port=3000)
        yield packet(owner, 0, port=4000)
        yield packet(owner, 1, port=4000)
        yield packet(owner, 31, port=4000)

    await owner.start_fixture(source())
    original = owner.demo.validate_receipt
    owner.demo.validate_receipt = inconsistent
    await asyncio.wait_for(owner.task, 35)
    assert owner.metrics["inference_count"] == 2
    assert owner.aggregator.snapshot()["quarantined_flow_keys"] == 1
    assert not owner.inference_blocked
    assert len(owner.snapshot()["research"]["unknown_attempts"]) == 1
    assert all(
        row["receipt"]["flow_id"] != first for row in owner.snapshot()["research"]["records"]
    )
    assert owner.store.runtime.verify_audit()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason,scope",
    [
        ("HELPER_CAPTURE_DROPS_DETECTED", "CAPTURE_WIDE"),
        ("HELPER_CAPTURE_COUNTER_UNAVAILABLE", "CAPTURE_WIDE"),
        ("STREAM_PACKET_SEQUENCE_MISMATCH", "CAPTURE_WIDE"),
        ("UNEXPLAINED_INPUT_FAILURE", "UNKNOWN"),
    ],
)
async def test_shared_or_unknown_failure_stops_both_domains(tmp_path, reason, scope):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())

    async def source():
        yield dns_packet(owner, 1)
        raise ValueError(reason)

    await owner.start_fixture(source())
    await owner.task
    s = owner.snapshot()
    assert owner.aborted and not s["collection_live"]
    assert s["network"]["integrity_scope"] == scope
    assert s["network"]["finalization"] == "BLOCKED"
    assert s["dns"]["diagnostic_status"] == "DNS_DIAGNOSTIC_BLOCKED"
    assert s["network"]["inference_count"] == 0
    assert s["research"]["records"] == []


@pytest.mark.asyncio
async def test_inflight_quarantine_prevents_investigation_and_other_key_can_continue(tmp_path):
    from tests.streaming_network_support import UnknownMockAdapter

    entered, release = asyncio.Event(), asyncio.Event()
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    adapter = UnknownMockAdapter()

    async def slow(request):
        adapter.calls += 1
        entered.set()
        await release.wait()
        return {"status": "UNKNOWN", "error": "ISOLATED_MOCK_CRASH_NO_MODEL_RECEIPT"}

    adapter.infer = slow

    async def source():
        for t in (0, 1, 31):
            yield packet(owner, t)
        await asyncio.wait_for(entered.wait(), 3)
        yield packet(owner, 0)
        release.set()

    await owner.start_fixture(source(), model_adapter=adapter)
    await asyncio.wait_for(owner.task, 5)
    assert adapter.calls == 1
    assert owner.metrics["inference_count"] == 0
    assert not owner.inference_blocked
    assert all(
        not r["receipt"] and not r["investigation"] for r in owner.snapshot()["research"]["records"]
    )
    assert owner.store.queue.counts() == {"DONE": 1}


def test_integrity_proof_tampering_is_not_accepted_as_a_new_receipt():
    from soc_agent.security_ai.research.total_integrity import TotalIntegrity

    with pytest.raises(ValueError):
        TotalIntegrity._check({"binding_digest": "0" * 64, "capture_session": str(uuid4())})


@pytest.mark.asyncio
async def test_crash_after_quarantine_audit_before_state_publish_does_not_restore_health(tmp_path):
    owner = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    parked = asyncio.Event()

    async def source():
        async for value in independent_source(owner):
            yield value
        while owner.metrics["inference_count"] != 2:
            await asyncio.sleep(0.02)
        parked.set()
        await asyncio.Event().wait()  # Simulated abrupt parent loss before finalization.

    await owner.start_fixture(source())
    await asyncio.wait_for(parked.wait(), 25)
    # Model the older periodic snapshot. Durable quarantine is already in audit.
    owner.store.runtime.update(
        network=dict(
            owner.metrics,
            finalization="RUNNING",
            quarantined_flow_count=0,
        )
    )
    owner.task.cancel()
    await asyncio.gather(owner.task, return_exceptions=True)
    await owner.consumer
    await owner.demo.stop()
    restored = StreamingMonitoring(tmp_path, total=True, paths=research_paths())
    snapshot = await restored.restore_latest()
    assert snapshot["network"]["quarantined_flow_count"] == 1  # Audit, not stale metrics.
    assert snapshot["network"]["recovery_terminal_verified"] is False
    assert snapshot["network"]["healthy_flow_count"] is None
    assert snapshot["network"]["inference_count"] == 0
    assert all(
        r["integrity_status_current"] == "RECOVERY_PENDING"
        and r["advisory_current"] == "WITHDRAWN_RESEARCH_ONLY"
        for r in snapshot["research"]["records"]
    )
