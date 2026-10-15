"""Actual pinned DNS Native + RF/LR artifacts; no capture, network traffic or provider."""

import asyncio
import hashlib
import json
from uuid import uuid4

import pytest

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.security_ai.research.models import AdvisoryContext, DNSReceipt, Request
from soc_agent.security_ai.research.service import ResearchDemo


@pytest.mark.asyncio
async def test_actual_native_domains_isolated_and_restored(tmp_path):
    b = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    initial = await b.dashboard()
    assert initial["research"]["dns_inference_count"] == 0
    assert initial["research"]["model_metrics"]["dns"]["state"] == "IDLE"
    assert not b.research_demo.directory.exists()
    await b.research_start()
    await b.research_replay("both", 2)
    await b.research_replay("dns", 0)
    r = await b.research_replay("dns", 1)
    assert r["inference_counts"] == {"quality": 1, "edge": 1} and r["dns_inference_count"] == 2
    assert r["flow_count"] == 1 and r["model_metrics"]["dns"]["successful"] == 2
    incidents = set()
    evidence = set()
    for record in r["records"]:
        inv = record["investigation"]
        incidents.add(inv["incident_id"])
        evidence.update(inv["evidence_references"])
        assert inv["status"] == "ASSESSED_READ_ONLY" and inv["provider_calls"] == 0
        assert inv["checkpoint_restored"] and inv["action_policy"] == "WRITE_DENIED"
        context = AdvisoryContext.model_validate(inv["context"])
        assert context.result.operational_inference == "BLOCKED"
        if record["receipt"]["profile"] == "dns":
            p = DNSReceipt.model_validate(record["receipt"])
            assert p.origin == "FIXTURE" and p.producer_parity == "UNVERIFIED"
            assert p.source_association == "FIXTURE_ONLY_NO_OPERATIONAL_SOURCE"
            assert p.validation_level == "FIXTURE_NATIVE_ONLY"
            state = inv["assessment"]["incident_state"]
            assert not state["observations"] and not state["hypotheses"]
            assert "Precomputed DNS9 fixture" in json.dumps(state["evidence"])
    assert len(incidents) == len(evidence) == 4
    assert (
        len({x["receipt"]["score"] for x in r["records"] if x["receipt"]["profile"] == "dns"}) == 2
    )
    db = b.research_demo._store().database.path
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    await b.dashboard()
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    await b.close()
    b = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    old = await b.research_status()
    assert old["demo_state"] == "STOPPED" and old["dns_inference_count"] == 2
    assert old["audit_integrity"] == "VERIFIED"
    await b.research_start("dns")
    cached = await b.research_replay("dns", 0)
    assert cached["replay_outcomes"] == ["CACHED_NO_NEW_INFERENCE"]
    assert cached["dns_inference_count"] == 2
    await b.close()


@pytest.mark.asyncio
async def test_dns_timeout_unknown_and_no_replay(tmp_path):
    d = ResearchDemo(tmp_path, timeout=0.1)
    await d.start("dns")
    r = await d.replay("dns", 0)
    assert r["status"] == "UNKNOWN" and r["record"]["error"] == "WORKER_TIMEOUT_NO_RETRY"
    assert (await d.replay("dns", 0))["status"] == "CACHED_NO_NEW_INFERENCE"
    s = d.snapshot()
    assert s["model_metrics"]["dns"]["unknown"] == 1
    assert s["dns_inference_count"] == 0 and s["operational_inference"] == "BLOCKED"


@pytest.mark.asyncio
async def test_dns_owned_crash_and_stop_recovery(tmp_path):
    d = ResearchDemo(tmp_path)
    await d.start("dns")
    task = asyncio.create_task(d.replay("dns", 1))
    for _ in range(500):
        if d.adapter.process:
            break
        await asyncio.sleep(0.01)
    assert d.adapter.process is not None
    assert d.snapshot()["model_metrics"]["dns"]["state"] == "RUNNING"
    d.adapter.process.kill()
    assert (await task)["status"] == "UNKNOWN"
    await d.stop()
    restored = ResearchDemo(tmp_path)
    s = restored.snapshot()
    assert s["demo_state"] == "STOPPED" and s["dns_inference_count"] == 0
    assert s["model_metrics"]["dns"]["unknown"] == 1 and s["audit_integrity"] == "VERIFIED"


@pytest.mark.asyncio
async def test_dns_dispatch_restart_no_automatic_retry(tmp_path, monkeypatch):
    d = ResearchDemo(tmp_path)
    await d.start("dns")

    async def fail(_):
        raise RuntimeError("OWNED_FAILURE_FIXTURE")

    monkeypatch.setattr(d.adapter, "infer", fail)
    with pytest.raises(RuntimeError):
        await d.replay("dns", 0)
    d = ResearchDemo(tmp_path)
    await d.start("dns")
    assert (await d.replay("dns", 0))["error"] == "PREVIOUS_OUTCOME_UNKNOWN_NO_RETRY"
    assert d.snapshot()["model_metrics"]["dns"]["unknown"] == 1


def test_dns_input_origin_and_cross_domain_contract():
    for origin in ("OFFLINE_PCAP", "NATIVE_AF_PACKET", "LIVE_WSL"):
        with pytest.raises(ValueError):
            Request(
                research_mode=True,
                profile="dns",
                flow_index=0,
                invocation_id=uuid4(),
                origin=origin,
            )
    with pytest.raises(ValueError):
        Request(
            research_mode=True, profile="dns", flow_index=2, invocation_id=uuid4(), origin="FIXTURE"
        )
