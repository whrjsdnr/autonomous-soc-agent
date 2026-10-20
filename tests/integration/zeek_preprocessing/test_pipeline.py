"""Native-protocol mocks and isolated temporary evidence; no privileged capture."""

import json

import pytest
from tests.integration.zeek_integrity.test_recovery import completed

from soc_agent.security_ai.collectors.live import LiveZeekCollector
from soc_agent.security_ai.collectors.preprocessing import final_summary


@pytest.mark.asyncio
async def test_native_preprocessing_certificate_audit_recovery_no_inference(tmp_path, monkeypatch):
    c = await completed(tmp_path, monkeypatch)
    try:
        value = c.snapshot()["preprocessing"]
        assert value["progress"]["normalized_packets"] == 4
        assert value["completed_flows"] == value["incomplete_flows"] == 1
        assert value["progress"]["finalization_reasons"] == {"IDLE_TIMEOUT": 1, "SHUTDOWN": 1}
        assert value["feature_decisions"] == {"BLOCKED_CAPTURE_INTEGRITY": 2}
        assert value["capture_integrity"] == "UNVERIFIED"
        assert value["source_digest"] == c.store.source.source_digest
        assert value["native_ai"] == value["dns9"] == value["operational_gate"] == "BLOCKED"
        assert not value["raw_payload_retained"] and c.producer is None
        audit = c.store.runtime.verify_audit()
        body = (c.directory / "preprocessing-proof.json").read_bytes()
        assert len(body) < 8192
        await c.stop()
        restored = LiveZeekCollector(tmp_path)
        state = await restored.recover()
        assert state["preprocessing"] == value
        assert restored.task is None and restored.producer is None
        assert restored.store.runtime.verify_audit() == audit
        assert (c.directory / "preprocessing-proof.json").read_bytes() == body
        assert not state["collection_live"] and state["research"]["records"] == []
        await restored.stop()
    finally:
        await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason,context",
    [
        ("USER_STOP", "COLLECTOR_STOP"),
        ("SESSION_TIMEOUT", "COLLECTOR_STOP"),
        ("CONTROLLER_STOP", "COLLECTOR_STOP"),
        ("EVENT_LIMIT_REACHED", "EVENT_LIMIT"),
        ("OUTPUT_LIMIT_REACHED", "OUTPUT_LIMIT"),
        ("PACKET_LIMIT_REACHED", "PACKET_LIMIT"),
    ],
)
async def test_termination_context_never_promotes_incomplete_window(
    tmp_path, monkeypatch, reason, context
):
    c = await completed(tmp_path, monkeypatch)
    try:
        # Pure projection fixture; original on-disk exit and evidence are not changed.
        c.result = {**c.result, "termination_reason": reason}
        value = final_summary(c, c.stream)
        assert value["termination_reason"] == reason
        assert value["collector_stop_context"] == context
        assert value["flow_quality_tail"][-1]["finalization_context"] == context
        assert value["flow_quality_tail"][-1]["completeness"] == "DEGRADED"
        assert value["native_ai"] == "BLOCKED" and c.producer is None
    finally:
        await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["file", "delete", "audit_binding"])
async def test_preprocessing_corruption_fails_closed_without_replay(tmp_path, monkeypatch, tamper):
    c = await completed(tmp_path, monkeypatch)
    path = c.directory / "preprocessing-proof.json"
    await c.stop()
    if tamper == "file":
        value = json.loads(path.read_text())
        value["capture_integrity"] = "VERIFIED"
        path.write_text(json.dumps(value))
    elif tamper == "delete":
        path.unlink()
    else:
        # Remove the certificate while leaving its bound append-only Audit event.
        path.rename(path.with_suffix(".preserved"))
    r = LiveZeekCollector(tmp_path)
    state = await r.recover()
    assert state["state"] == "ERROR" and state["last_error"] == "ZEEK_PREPROCESSING_PROOF_MISMATCH"
    assert r.producer is None and r.task is None and not state["collection_live"]
    assert state["research"]["records"] == []
    await r.stop()


@pytest.mark.asyncio
async def test_native_source_cannot_gain_offline_gate_by_fixture_flag(tmp_path, monkeypatch):
    c = await completed(tmp_path, monkeypatch)
    try:
        c.fixture = True  # Deliberate internal-state fault injection, not an admission path.
        value = final_summary(c, c.stream)
        assert value["feature_decisions"] == {"BLOCKED_CAPTURE_INTEGRITY": 2}
        assert value["input_origin"] == "ZEEK_NATIVE_LIVE"
        assert value["native_ai"] == "BLOCKED"
    finally:
        c.fixture = False
        await c.stop()


@pytest.mark.asyncio
async def test_crash_between_summary_publish_and_audit_append_is_not_trusted(tmp_path, monkeypatch):
    from soc_agent.security_ai.collectors.finalization import publish

    # Simulate the publication/transaction boundary without touching an existing session.
    monkeypatch.setattr(
        "soc_agent.security_ai.collectors.preprocessing_store.persist",
        lambda c: final_summary(c, c.stream),
    )
    c = await completed(tmp_path, monkeypatch)
    path = c.directory / "preprocessing-proof.json"
    assert not path.exists()
    publish(path, c.preprocessing)
    audit = c.store.runtime.verify_audit()
    await c.stop()
    restored = LiveZeekCollector(tmp_path)
    value = await restored.recover()
    assert value["last_error"] == "ZEEK_PREPROCESSING_PROOF_MISMATCH"
    assert value["state"] == "ERROR" and not value["collection_live"]
    assert restored.task is None and restored.producer is None
    assert restored.store.runtime.verify_audit() == audit
    await restored.stop()
