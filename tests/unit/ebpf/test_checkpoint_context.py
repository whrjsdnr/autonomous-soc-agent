"""Synthetic contexts; old Native bytes are exercised separately, never rewritten."""

import copy
import json

import pytest

from soc_agent.security_ai.ebpf.checkpoint import decode_checkpoint, encode_checkpoint
from soc_agent.security_ai.research.models import digest


def summary(count=9):
    rows = [
        dict(
            flow_id=f"{n:064x}",
            values_digest=f"{n + 1024:064x}",
            packet_count=n + 1,
            eligible=False,
            provenance="Synthetic only / 한글" * 20,
            lifecycle=dict(
                first_event_ns=n + 1,
                last_event_ns=n + 2,
                protocol="tcp",
                capture_window="UNVERIFIED",
                termination_authority="COLLECTOR_FINALIZATION_NOT_FLOW_COMPLETION",
                timeout_witness_ns=None,
            ),
        )
        for n in range(count)
    ]
    tail = [
        row | dict(feature_names=[f"feature-{n}" for n in range(14)], values=[1.0] * 14)
        for row in rows[-4:]
    ]
    return dict(candidate_eligibility=rows, feature_tail=tail, context="session" * 1200)


def test_nested_and_vector_context_saves_space_without_changing_any_observation():
    value = summary()
    before = copy.deepcopy(value)
    assert len(json.dumps(value).encode()) > 16384
    text = encode_checkpoint(value)
    assert json.loads(text)["checkpoint_encoding"] == "SHARED_CONTEXT_V2"
    assert len(text.encode()) < 16384
    assert decode_checkpoint(text) == value == before
    assert digest(decode_checkpoint(text)) == digest(value)
    assert encode_checkpoint(dict(reversed(list(value.items())))) == text
    changed = copy.deepcopy(value)
    changed["candidate_eligibility"].reverse()
    assert decode_checkpoint(encode_checkpoint(changed)) == changed
    assert encode_checkpoint(changed) != text


@pytest.mark.parametrize(
    "mutation",
    [
        "extra",
        "summary_overlap",
        "group_extra",
        "row_overlap",
        "lifecycle_overlap",
        "wrong_rows",
        "expansion",
    ],
)
def test_v2_malformed_context_rejected(mutation):
    body = json.loads(encode_checkpoint(summary()))
    group = body["candidates"]
    if mutation == "extra":
        body["unexpected"] = 1
    elif mutation == "summary_overlap":
        body["summary"]["candidate_eligibility"] = []
    elif mutation == "group_extra":
        group["unexpected"] = 1
    elif mutation == "row_overlap":
        group["rows"][0]["eligible"] = True
    elif mutation == "lifecycle_overlap":
        group["rows"][0]["lifecycle"]["protocol"] = "udp"
    elif mutation == "wrong_rows":
        group["rows"] = [False]
    else:
        body["summary"] = {}
        group["shared"] = {"context": "x" * 8300}
        group["rows"] = [{}] * 1024
    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_(ENCODING|SIZE)"):
        decode_checkpoint(json.dumps(body, separators=(",", ":")))


def test_old_v1_and_plain_json_still_restore_without_upgrading_evidence():
    old = json.dumps(
        dict(
            checkpoint_encoding="SHARED_RCA_V1",
            summary={"received": 2},
            shared={"eligible": False},
            rows=[{"flow_id": "a"}, {"flow_id": "b"}],
        )
    )
    assert decode_checkpoint(old) == dict(
        received=2,
        candidate_eligibility=[
            dict(eligible=False, flow_id="a"),
            dict(eligible=False, flow_id="b"),
        ],
    )
    assert decode_checkpoint('{"candidate_eligibility":[]}') == {"candidate_eligibility": []}


def test_unicode_long_distinct_context_overflow_never_silently_discards_receipts():
    value = summary(1024)
    for n, row in enumerate(value["candidate_eligibility"]):
        row["provenance"] = f"{n:04}" + ("긴 증거" * 200)
    before = copy.deepcopy(value)
    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_SIZE"):
        encode_checkpoint(value)
    assert value == before and len(value["candidate_eligibility"]) == 1024


@pytest.mark.asyncio
async def test_failed_oversize_save_keeps_previous_checkpoint_and_recoverable_audit(
    tmp_path, monkeypatch
):
    from tests.ebpf_support import plan

    from soc_agent.security_ai.ebpf.collector import EBPFCollector

    collector = EBPFCollector(tmp_path / "session", plan())
    collector.prepare_metadata()
    old = collector._summary()
    collector._persist_checkpoint(encode_checkpoint(old), digest(old))
    # Use the store's transaction interface; no test-only persistence replacement.
    with collector.store.database.transaction() as db:
        previous = tuple(db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone())
    monkeypatch.setattr(
        collector, "_summary", lambda: dict(candidate_eligibility=[], extra="x" * 17000)
    )
    with pytest.raises(ValueError, match="EBPF_CHECKPOINT_SIZE"):
        collector._checkpoint_text()
    with collector.store.database.transaction() as db:
        assert tuple(db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone()) == previous
    restored = await EBPFCollector(collector.directory, collector.plan).recover()
    assert restored["restored_evidence"] == old
    assert restored["runtime_audit_integrity"] == collector.store.verify_audit()
