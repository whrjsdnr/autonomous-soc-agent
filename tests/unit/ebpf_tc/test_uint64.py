"""Real fixed ABI + SQLite JSON path, without authentication or Kernel execution."""

import hashlib
import json
import struct
from uuid import UUID

import pytest
from pydantic import ValidationError
from tests.ebpf_support import plan

from soc_agent.security_ai.ebpf.collector import EBPFCollector
from soc_agent.security_ai.ebpf.ring import ABI, decode
from soc_agent.security_ai.ebpf_broker.contracts import Command
from soc_agent.security_ai.ebpf_native.contracts import RunIdentity
from soc_agent.security_ai.ebpf_tc.contracts import REQUEST, request
from soc_agent.security_ai.ebpf_tc.journal import RC_ROW, recover_native
from soc_agent.security_ai.research.models import digest


@pytest.mark.asyncio
@pytest.mark.parametrize("generation", [1, 2**63 - 1, 2**63, 2**64 - 1])
async def test_request_event_json_sqlite_and_digest_roundtrip(tmp_path, generation):
    p = plan(generation=generation)
    run = RunIdentity(
        application_session=p.session_id,
        generation=UUID(bytes=generation.to_bytes(8, "little") + b"\x01" * 8),
        scope_digest="a" * 64,
        run_number=1,
    )
    assert (
        REQUEST.unpack(
            request(Command(command="ATTACH", plan_digest="a" * 64, sequence=1, run=run))
        )[2]
        == generation
    )
    raw = ABI.pack(
        generation,
        1000,
        1,
        1,
        0,
        42,
        28,
        10001,
        53,
        4,
        17,
        0,
        1,
        bytes([127, 0, 0, 1]) + bytes(12),
        bytes([127, 0, 0, 53]) + bytes(12),
    )
    assert decode(raw, p, 1).generation == generation
    c = EBPFCollector(tmp_path / "collector", p)
    try:
        await c.prepare()
        with c.store.database.transaction() as db:
            text, stored_digest = db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone()
        value = json.loads(text)
        assert value["plan"]["generation"] == generation
        assert stored_digest == digest(value)
        assert c.store.verify_audit()
        restored = EBPFCollector(c.directory, p)
        await restored.recover()
        assert restored.plan.generation == generation
        assert restored.state == "RESTORED_NO_REATTACH"
    finally:
        await c.stop()


@pytest.mark.parametrize("generation", [0, -1, 2**64, True, 1.0])
def test_generation_range_is_not_coerced(generation):
    with pytest.raises(ValidationError):
        plan(generation=generation)


@pytest.mark.parametrize("generation", [7, 2**63, 2**64 - 1])
def test_historical_signed_writer_bytes_and_digest_remain_compatible(tmp_path, generation):
    signed = generation if generation < 2**63 else generation - 2**64
    payload = struct.pack("<10q", 1, -11, 12, 12, 0, 0, -32, 123, signed, 5)
    body = RC_ROW.pack(
        bytes.fromhex("aa" * 32), b"DATA_COUNTER_QUERY", payload, 1, 1, bytes(32), bytes(32)
    )
    body = body[:-32] + hashlib.sha256(body[:-32]).digest()
    journal = tmp_path / "historical.bin"
    journal.write_bytes(body)
    value = recover_native(journal, "aa" * 32)
    assert value["data_counter_queries"][0]["generation"] == generation
    assert payload == struct.pack("<8qQq", 1, -11, 12, 12, 0, 0, -32, 123, generation, 5)
    assert journal.read_bytes() == body
    assert not value["claimed_cleanup"] and not value["authentication_restored"]
