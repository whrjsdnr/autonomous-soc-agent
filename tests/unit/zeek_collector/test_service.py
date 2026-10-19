import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from tests.zeek_collector_support import row

from soc_agent.gui.backend import Backend, GUIConfig
from soc_agent.security_ai.collectors.zeek import FixtureCollector, ZeekCollector
from soc_agent.security_ai.research.models import digest


@pytest.mark.asyncio
async def test_duplicate_out_of_order_persistence_audit_recovery(tmp_path):
    c = FixtureCollector(tmp_path)
    await c.prepare_logs(
        {"conn.log": row() + row() + row(uid="Cearlier", ts=1), "dns.log": row("dns")}
    )
    await c.start()
    await c.task
    assert c.state == "STOPPED", c.last_error
    assert (
        c.metrics()["network_events"] == 2 and c.metrics()["dns_events"] == 1 and c.duplicates == 1
    )
    assert c.out_of_order == 1 and c.metrics()["queue_depth"] == 0
    before = [e["event_id"] for e in c.store.events()]
    assert c.snapshot()["runtime_audit_integrity"] == "VERIFIED"
    assert c.snapshot()["research"]["records"] == []
    recovered = ZeekCollector(tmp_path)
    await recovered.recover()
    assert [e["event_id"] for e in recovered.store.events()] == before
    assert recovered.rows_read == 0 and recovered.snapshot()["collection_live"] is False
    assert recovered.metrics()["inference_count"] == 0
    await c.stop()
    await recovered.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["conflict", "partial", "privacy", "disk"])
async def test_failures_never_produce_ai_receipts(tmp_path, fault):
    c = FixtureCollector(tmp_path)
    logs = {"conn.log": row(), "dns.log": row("dns")}
    if fault == "conflict":
        logs["conn.log"] += row(orig_pkts=3)
    if fault == "partial":
        logs["conn.log"] = row()[:-1]
    await c.prepare_logs(logs)
    if fault == "privacy":
        # Valid log manifest is deliberately forged only in this isolated fixture DB.
        (c.directory / "logs/conn.log").write_bytes(row(uid="Ctamp"))
    if fault == "disk":
        c._budget = Mock(side_effect=ValueError("ZEEK_SESSION_DISK_BUDGET_EXCEEDED"))
    await c.start()
    await c.task
    assert c.state == "ERROR" and c.last_error.startswith("ZEEK_")
    assert c.snapshot()["research"]["records"] == [] and not c.snapshot()["collection_live"]
    assert c.snapshot()["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
    await c.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["audit", "event_and_digest", "cursor_and_digest"])
async def test_audit_binding_rejects_metadata_rewrite(tmp_path, tamper):
    c = FixtureCollector(tmp_path)
    await c.prepare_logs({"conn.log": row(), "dns.log": b""})
    await c.start()
    await c.task
    with c.store.runtime.database.transaction() as db:
        if tamper == "audit":
            db.execute("UPDATE monitor_audit SET digest=? WHERE sequence=1", ("f" * 64,))
        elif tamper == "event_and_digest":
            value = json.loads(db.execute("SELECT payload FROM collector_events").fetchone()[0])
            value["forward_packets"] = 999
            db.execute(
                "UPDATE collector_events SET payload=?,digest=?", (json.dumps(value), digest(value))
            )
        else:
            value = json.loads(db.execute("SELECT value FROM collector_cursors").fetchone()[0])
            value["offset"] = 0
            db.execute(
                "UPDATE collector_cursors SET value=?,digest=?", (json.dumps(value), digest(value))
            )
    snap = c.snapshot()
    assert snap["state"] == "UNKNOWN" and snap["runtime_audit_integrity"] == "INVALID"
    assert snap["collector"]["events"] == []


@pytest.mark.asyncio
async def test_live_and_concurrent_collectors_are_blocked(tmp_path):
    runner = Mock()
    c = ZeekCollector(tmp_path, runner=runner)
    with pytest.raises(ValueError, match="SEPARATE_APPROVAL"):
        await c.prepare(pcap=tmp_path / "none", sha256="a" * 64, mode="live")
    runner.environment.assert_not_called()
    b = Backend(GUIConfig(data_directory=tmp_path / "gui"))
    pending = asyncio.create_task(asyncio.sleep(60))
    try:
        b._owners["total_monitoring"] = SimpleNamespace(task=pending, preparing=False)
        with pytest.raises(ValueError, match="COLLECTOR_ALREADY_ACTIVE"):
            await b.zeek_start("unused", "a" * 64)
        assert "zeek_collector" not in b._owners
    finally:
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_admission_queue_overflow_and_no_receipt(tmp_path, monkeypatch):
    from soc_agent.security_ai.collectors.reader import LogReader

    c = FixtureCollector(tmp_path)
    await c.prepare_logs({"conn.log": row(), "dns.log": b""})
    monkeypatch.setattr(LogReader, "read", lambda self, *a: ([row()] * 33, {}))
    await c.start()
    await c.task
    assert c.last_error == "ZEEK_INGESTION_QUEUE_OVERFLOW"
    assert c.metrics()["inference_count"] == 0 and not c.network_events()
    assert c.store.runtime.verify_audit()


@pytest.mark.asyncio
async def test_local_json_markdown_export_has_provenance_and_no_fabricated_ai(tmp_path):
    from soc_agent.security_ai.collectors.export import export

    c = FixtureCollector(tmp_path)
    await c.prepare_logs({"conn.log": row(), "dns.log": row("dns")})
    await c.start()
    await c.task
    export(c, tmp_path / "result.json", "json")
    export(c, tmp_path / "result.md", "markdown")
    e = json.loads((tmp_path / "result.json").read_text())
    assert e["inference_receipts"] == [] and e["source"]["origin"] == "SYNTHETIC_ZEEK_JSON"
    assert (
        e["operational_gate"] == "BLOCKED" and e["audit_digest"] == c.store.runtime.verify_audit()
    )
    assert [v["collector_sequence"] for v in e["events"]] == [1, 2]
    assert "Not an AI finding" in (tmp_path / "result.md").read_text()
    with pytest.raises((OSError, ValueError)):
        export(c, tmp_path / "result.json", "json")


@pytest.mark.asyncio
async def test_missing_checkpoint_and_incomplete_process_recovery_fail_closed(tmp_path):
    c = FixtureCollector(tmp_path)
    await c.prepare_logs({"conn.log": row()})
    await c.start()
    await c.task
    with c.store.runtime.database.transaction() as db:
        db.execute("DELETE FROM collector_cursors")
    recovered = ZeekCollector(tmp_path)
    with pytest.raises(ValueError, match="CURSOR_AUDIT_BINDING"):
        await recovered.recover()
    assert recovered.state == "ERROR" and recovered.writer is None
    assert recovered.last_error == "ZEEK_CURSOR_AUDIT_BINDING_FAILED"


@pytest.mark.asyncio
async def test_process_crash_is_audited_no_recovery_restart(tmp_path):
    from tests.zeek_collector_support import pcap_fixture

    pcap = tmp_path / "fixture.pcap"
    sha = pcap_fixture(pcap)
    runner = Mock()
    runner.run.side_effect = ValueError("ZEEK_PROCESS_FAILED")
    c = ZeekCollector(tmp_path, runner=runner)
    await c.prepare(pcap=pcap, sha256=sha)
    await c.start()
    await c.task
    assert c.state == "ERROR" and c.last_error == "ZEEK_PROCESS_FAILED"
    assert c.snapshot()["runtime_audit_integrity"] == "VERIFIED"
    recovered = ZeekCollector(tmp_path)
    with pytest.raises(ValueError, match="COMPLETION_UNVERIFIED"):
        await recovered.recover()
    assert recovered.state == "ERROR" and recovered.writer is None
    assert recovered.snapshot()["research"]["records"] == []
    runner.run.assert_called_once()
